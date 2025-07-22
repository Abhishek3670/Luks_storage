mod cctv_manager;
use actix_multipart::{form::{tempfile::TempFile, MultipartForm}};
use sysinfo::System;
use actix_files::Files;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::header, Error};
use actix_web::web::Query;
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_web_flash_messages::{FlashMessage, IncomingFlashMessages, FlashMessagesFramework};
use std::sync::{Arc, Mutex};
use std::process::Stdio;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use serde_json;
use tera::{Tera, Context};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use tokio::process::Command;
use tokio::fs;
use mime_guess::from_path;
use std::os::unix::fs::MetadataExt;
use sqlx::SqlitePool;
use argon2::{
    password_hash::{rand_core, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use std::collections::HashMap;
use log::debug;

// --- 1. Configuration & State ---
#[derive(Clone, Serialize)]
struct Config {
    device_path: String,
    mapper_name: String,
    mount_point: String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            device_path: std::env::var("LUKS_DEVICE_PATH").unwrap_or_else(|_| "/dev/sdb1".to_string()),
            mapper_name: std::env::var("LUKS_MAPPER_NAME").unwrap_or_else(|_| "encrypted_volume".to_string()),
            mount_point: std::env::var("LUKS_MOUNT_POINT").unwrap_or_else(|_| "/mnt/secure_data".to_string()),
        }
    }
}

#[derive(Clone)]
struct AppState {
    is_mounted: Arc<Mutex<bool>>,
    config: Config,
    db: SqlitePool,
    tera: Tera,
    cctv_manager: Arc<Mutex<cctv_manager::CctvManager>>,
}
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UnlockRequest {
    luks_password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub last_login: Option<String>,
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    is_dir: bool,
    size: u64,
    relative_path: String,
}

#[derive(Deserialize)]
struct DashboardQuery {
    path: Option<String>,
}

#[derive(Deserialize)]
struct CreateFolderRequest {
    folder_name: String,
    current_path: String,
}

#[derive(Deserialize)]
struct RenameRequest {
    old_name: String,
    new_name: String,
    current_path: String,
}

#[derive(Deserialize)]
struct DeleteRequest {
    item_name: String,
    current_path: String,
}

#[derive(Deserialize)]
struct CopyRequest {
    source_paths: Vec<String>,
    destination_path: String,
}

#[derive(Deserialize)]
struct MoveRequest {
    source_paths: Vec<String>,
    destination_path: String,
}

#[derive(Deserialize)]
struct AddUserRequest {
    username: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
struct DeleteUserRequest {
    user_id: i64,
}

#[derive(Deserialize)]
struct EditUserRequest {
    user_id: i64,
    password: Option<String>,
    role: String,
}

#[derive(Deserialize)]
struct AddPermissionRequest {
    user_id: i64,
    can_read: bool,
    can_write: bool,
    can_delete: bool,
    can_share: bool,
}

#[derive(Deserialize)]
struct DeletePermissionRequest {
    user_id: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Permission {
    pub id: i64,
    pub user_id: i64,
    pub path: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_delete: bool,
    pub can_share: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    #[multipart(limit = "100MB")]
    files: Vec<TempFile>,
    current_path: actix_multipart::form::text::Text<String>,
}
async fn check_if_mounted(mount_point: &str) -> bool {
    let path = Path::new(mount_point);
    if !path.is_dir() { return false; }
    if path.canonicalize().unwrap_or_default() == Path::new("/").canonicalize().unwrap_or_default() { return true; }
    let parent_path = match path.parent() { Some(p) => p, None => return false };
    let path_meta = match fs::metadata(path).await { Ok(meta) => meta, Err(_) => return false };
    let parent_meta = match fs::metadata(parent_path).await { Ok(meta) => meta, Err(_) => return false };
    let is_mounted = path_meta.dev() != parent_meta.dev();
    if is_mounted { log::info!("Verified that {} is an active mount point.", mount_point); }
    else { log::info!("Path {} exists but is not a mount point.", mount_point); }
    is_mounted
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();
    Ok(password_hash)
}

fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = match argon2::PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

/// Check if a user has the required permission for a given path.
/// `action` can be "read", "write", "delete", or "share".
pub async fn check_user_permission(
    db: &SqlitePool,
    user_id: i64,
    path: &str,
    action: &str,
) -> Result<bool, sqlx::Error> {
    // Admins always have all permissions
    let user_role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(db)
        .await?;
    if let Some(role) = user_role {
        if role == "admin" {
            return Ok(true);
        }
    }

    // Check for explicit permission on the path or any parent path
    let mut current_path = path;
    loop {
        let row = sqlx::query!(
            "SELECT can_read, can_write, can_delete, can_share FROM permissions WHERE user_id = ? AND path = ?",
            user_id, current_path
        )
        .fetch_optional(db)
        .await?;
        if let Some(perm) = row {
            let allowed = match action {
                "read" => perm.can_read,
                "write" => perm.can_write,
                "delete" => perm.can_delete,
                "share" => perm.can_share,
                _ => false,
            };
            return Ok(allowed);
        }
        // Move up to parent directory
        if let Some(pos) = current_path.rfind('/') {
            if pos == 0 {
                current_path = "/";
            } else {
                current_path = &current_path[..pos];
            }
        } else {
            break;
        }
    }
    // Default: allow read, deny others
    Ok(action == "read")
}


// --- 4. Route Handlers ---
async fn show_dashboard(session: Session, app_state: web::Data<AppState>, flash_messages: IncomingFlashMessages, query: web::Query<DashboardQuery>) -> Result<HttpResponse, Error> {
    let user = match session.get::<User>("user")? {
        Some(user) => user,
        None => { return Ok(HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish()); }
    };

    let mut context = Context::new();
    context.insert("user", &user);
    let is_mounted = *app_state.is_mounted.lock().unwrap();
    context.insert("is_mounted", &is_mounted);
    context.insert("config", &app_state.config);
    let messages: Vec<FlashMessage> = flash_messages.iter().cloned().collect();
    context.insert("messages", &messages);
    let user_path = query.into_inner().path.unwrap_or_else(String::new);
    context.insert("current_path", &user_path);

    if is_mounted {
        let base_path = PathBuf::from(&app_state.config.mount_point);
        let mut current_abs_path = base_path.clone();
        current_abs_path.push(&user_path);
        if !current_abs_path.starts_with(&base_path) {
            FlashMessage::error("Invalid path specified.").send();
            return Ok(HttpResponse::Found().insert_header((header::LOCATION, "/")).finish());
        }
        let mut files: Vec<FileEntry> = Vec::new();
        if let Ok(mut entries) = fs::read_dir(&current_abs_path).await {
            while let Some(entry) = entries.next_entry().await? {
                let metadata = entry.metadata().await?;
                let name = entry.file_name().into_string().unwrap_or_default();
                let relative_path = Path::new(&user_path).join(&name).to_string_lossy().to_string();
                files.push(FileEntry { name, is_dir: metadata.is_dir(), size: metadata.len(), relative_path });
            }
        }
        files.sort_by(|a, b| {
            if a.is_dir == b.is_dir { a.name.to_lowercase().cmp(&b.name.to_lowercase()) }
            else if a.is_dir { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater }
        });
        context.insert("files", &files);
    }
    
    let rendered = app_state.tera.render("index.html", &context).unwrap();
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

async fn show_login_form(app_state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().content_type("text/html").body(app_state.tera.render("login.html", &Context::new()).unwrap())
}

// Update show_admin_users to support search
async fn show_admin_users(
    session: Session,
    app_state: web::Data<AppState>,
    query: Query<HashMap<String, String>>,
) -> impl Responder {
    let user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };
    let search = query.get("q").map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let users = if !search.is_empty() {
        sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, role, last_login FROM users WHERE lower(username) LIKE ? OR lower(role) LIKE ? ORDER BY COALESCE(last_login, '1970-01-01T00:00:00Z') DESC"
        )
        .bind(format!("%{}%", search))
        .bind(format!("%{}%", search))
        .fetch_all(&app_state.db)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, role, last_login FROM users ORDER BY COALESCE(last_login, '1970-01-01T00:00:00Z') DESC"
        )
        .fetch_all(&app_state.db)
        .await
        .unwrap_or_default()
    };
    let mut context = Context::new();
    context.insert("users", &users);
    context.insert("current_user_id", &user.id);
    context.insert("user", &user);
    context.insert("search_term", &search);
    HttpResponse::Ok().content_type("text/html").body(app_state.tera.render("admin_users.html", &context).unwrap())
}

async fn show_add_user_form(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };
    let mut context = Context::new();
    context.insert("user", &user);
    HttpResponse::Ok().content_type("text/html").body(app_state.tera.render("admin_user_form.html", &context).unwrap())
}

async fn add_user(form: web::Form<AddUserRequest>, app_state: web::Data<AppState>) -> impl Responder {
    let hashed_password = match hash_password(&form.password) {
        Ok(h) => h,
        Err(_) => {
            FlashMessage::error("Failed to process password.").send();
            return HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish();
        }
    };

    match sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
        .bind(&form.username)
        .bind(hashed_password)
        .bind(&form.role)
        .execute(&app_state.db)
        .await
    {
        Ok(_) => FlashMessage::success(format!("User '{}' created successfully.", form.username)).send(),
        Err(e) => FlashMessage::error(format!("Failed to create user: {}", e)).send(),
    }
    HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish()
}

async fn delete_user(session: Session, form: web::Form<DeleteUserRequest>, app_state: web::Data<AppState>) -> impl Responder {
    let current_user = session.get::<User>("user").unwrap().unwrap();
    if current_user.id == form.user_id {
        FlashMessage::error("You cannot delete your own account.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish();
    }

    let user_to_delete = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?").bind(form.user_id).fetch_one(&app_state.db).await.unwrap();
    if user_to_delete.role == "admin" {
        let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetch_one(&app_state.db).await.unwrap_or(0);
        if admin_count <= 1 {
            FlashMessage::error("Cannot delete the last admin user.").send();
            return HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish();
        }
    }

    match sqlx::query("DELETE FROM users WHERE id = ?").bind(form.user_id).execute(&app_state.db).await {
        Ok(_) => FlashMessage::success("User deleted successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to delete user: {}", e)).send(),
    }
    HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish()
}

// Show edit user form
async fn show_edit_user_form(
    session: Session,
    app_state: web::Data<AppState>,
    path: web::Path<i64>
) -> impl Responder {
    let user_id = path.into_inner();
    debug!("Edit handler: Looking up user_id: {}", user_id);
    let current_user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };
    // Select all columns to match User struct
    let user = match sqlx::query_as::<_, User>("SELECT id, username, password_hash, role, last_login FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&app_state.db)
        .await {
            Ok(user) => user,
            Err(e) => {
                debug!("User not found for id {}: {:?}", user_id, e);
                return HttpResponse::NotFound().body("User not found");
            },
        };
    let mut context = Context::new();
    context.insert("edit_user", &user);
    context.insert("current_user", &current_user);
    context.insert("user", &current_user);
    HttpResponse::Ok().body(app_state.tera.render("admin_user_edit.html", &context).unwrap())
}

// Handle edit user form submission
async fn edit_user(
    session: Session,
    app_state: web::Data<AppState>,
    form: web::Form<EditUserRequest>,
) -> impl Responder {
    let current_user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };
    // Prevent removing last admin
    if form.role != "admin" {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(form.user_id)
            .fetch_one(&app_state.db)
            .await
            .unwrap();
        if user.role == "admin" {
            let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                .fetch_one(&app_state.db)
                .await
                .unwrap_or(0);
            if admin_count <= 1 {
                FlashMessage::error("Cannot remove the last admin user.").send();
                return HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish();
            }
        }
    }
    // Update password if provided
    if let Some(ref password) = form.password {
        if !password.is_empty() {
            let hashed_password = match hash_password(password) {
                Ok(h) => h,
                Err(_) => {
                    FlashMessage::error("Failed to process password.").send();
                    return HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish();
                }
            };
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
                .bind(hashed_password)
                .bind(form.user_id)
                .execute(&app_state.db)
                .await
                .unwrap();
        }
    }
    // Update role
    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
        .bind(&form.role)
        .bind(form.user_id)
        .execute(&app_state.db)
        .await
        .unwrap();
    FlashMessage::success("User updated successfully.").send();
    HttpResponse::Found().insert_header((header::LOCATION, "/admin/users")).finish()
}

// Show admin permissions page
async fn show_admin_permissions(
    session: Session,
    app_state: web::Data<AppState>,
    flash_messages: IncomingFlashMessages,
) -> impl Responder {
    let user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };

    // Get all permissions with user information (only root path)
    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT p.id, p.user_id, p.path, p.can_read, p.can_write, p.can_delete, p.can_share, p.created_at, p.updated_at 
         FROM permissions p 
         WHERE p.path = '/'
         ORDER BY p.user_id"
    )
    .fetch_all(&app_state.db)
    .await
    .unwrap_or_default();

    // Get all users for the dropdown
    let users = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, last_login FROM users ORDER BY username"
    )
    .fetch_all(&app_state.db)
    .await
    .unwrap_or_default();

    let mut context = Context::new();
    context.insert("permissions", &permissions);
    context.insert("users", &users);
    context.insert("user", &user);
    let messages: Vec<FlashMessage> = flash_messages.iter().cloned().collect();
    context.insert("messages", &messages);
    
    HttpResponse::Ok().content_type("text/html").body(app_state.tera.render("admin_permissions.html", &context).unwrap())
}

// Add new permission
async fn add_permission(
    session: Session,
    app_state: web::Data<AppState>,
    form: web::Form<AddPermissionRequest>,
) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };

    match sqlx::query!(
        "INSERT INTO permissions (user_id, path, can_read, can_write, can_delete, can_share, created_at, updated_at) \
         VALUES (?, '/', ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) \
         ON CONFLICT(user_id, path) DO UPDATE SET can_read=excluded.can_read, can_write=excluded.can_write, can_delete=excluded.can_delete, can_share=excluded.can_share, updated_at=CURRENT_TIMESTAMP",
        form.user_id, form.can_read, form.can_write, form.can_delete, form.can_share
    )
    .execute(&app_state.db)
    .await
    {
        Ok(_) => FlashMessage::success("Permission added/updated successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to add permission: {}", e)).send(),
    }
    
    HttpResponse::Found().insert_header((header::LOCATION, "/admin/permissions")).finish()
}

// Delete permission
async fn delete_permission(
    session: Session,
    app_state: web::Data<AppState>,
    form: web::Form<DeletePermissionRequest>,
) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };

    match sqlx::query("DELETE FROM permissions WHERE user_id = ? AND path = '/'")
        .bind(form.user_id)
        .execute(&app_state.db)
        .await
    {
        Ok(_) => FlashMessage::success("Permission deleted successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to delete permission: {}", e)).send(),
    }
    
    HttpResponse::Found().insert_header((header::LOCATION, "/admin/permissions")).finish()
}

async fn login(form: web::Form<LoginRequest>, session: Session, app_state: web::Data<AppState>) -> impl Responder {
    log::info!("Login attempt for user: {}", form.username);
    
    let user = match sqlx::query_as::<_, User>("SELECT id, username, password_hash, role, last_login FROM users WHERE username = ?")
        .bind(&form.username).fetch_optional(&app_state.db).await {
            Ok(Some(user)) => {
                log::info!("User found: {}", user.username);
                user
            },
            _ => {
                log::warn!("User not found: {}", form.username);
                FlashMessage::warning("Invalid credentials.").send();
                return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish();
            }
        };

    log::info!("Verifying password for user: {}", user.username);
    let password_valid = verify_password(&user.password_hash, &form.password);
    log::info!("Password verification result: {}", password_valid);
    
    if password_valid {
        session.insert("user", &user).unwrap();
        // Update last_login for the user
        sqlx::query("UPDATE users SET last_login = datetime('now') WHERE id = ?")
            .bind(user.id)
            .execute(&app_state.db)
            .await
            .ok();
        FlashMessage::info("Login successful!").send();
        log::info!("Login successful for user: {}", user.username);
        HttpResponse::Found().insert_header((header::LOCATION, "/")).finish()
    } else {
        log::warn!("Password verification failed for user: {}", user.username);
        FlashMessage::warning("Invalid credentials.").send();
        HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish()
    }
}

async fn logout(session: Session) -> impl Responder {
    session.clear();
    FlashMessage::info("You have been successfully logged out.").send();
    HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish()
}

async fn unlock_drive(form: web::Form<UnlockRequest>, app_state: web::Data<AppState>) -> impl Responder {
    let mut open_cmd = Command::new("sudo");
    open_cmd.arg("cryptsetup").arg("luksOpen").arg(&app_state.config.device_path).arg(&app_state.config.mapper_name)
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = open_cmd.spawn().expect("Failed to spawn cryptsetup command");
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(form.luks_password.as_bytes()).await.unwrap();
    }
    let output = child.wait_with_output().await.unwrap();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        FlashMessage::error(format!("Failed to unlock device: {}", stderr)).send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }

    let mount_point = &app_state.config.mount_point;
    if let Err(_) = tokio::fs::create_dir_all(mount_point).await {
        FlashMessage::error("Server error: Could not create mount point directory.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let mount_output = Command::new("sudo").arg("mount").arg(format!("/dev/mapper/{}", &app_state.config.mapper_name)).arg(mount_point).output().await.unwrap();
    if !mount_output.status.success() {
        let stderr = String::from_utf8_lossy(&mount_output.stderr);
        let _ = Command::new("sudo").arg("cryptsetup").arg("luksClose").arg(&app_state.config.mapper_name).status().await;
        FlashMessage::error(format!("Failed to mount device: {}", stderr)).send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
    let chown_output = Command::new("sudo").arg("chown").arg("-R").arg(format!("{}:{}", user, user)).arg(mount_point).output().await.unwrap();
    if !chown_output.status.success() {
        let stderr = String::from_utf8_lossy(&chown_output.stderr);
        log::error!("chown command failed: {}", stderr);
    } else {
        log::info!("Successfully changed ownership of {} to user {}", mount_point, user);
    }
    *app_state.is_mounted.lock().unwrap() = true;
    FlashMessage::success("Device unlocked and mounted successfully!").send();
    HttpResponse::Found().insert_header((header::LOCATION, "/")).finish()
}

async fn lock_drive(app_state: web::Data<AppState>) -> impl Responder {
    let umount_output = Command::new("sudo").arg("umount").arg(&app_state.config.mount_point).output().await.unwrap();
    if !umount_output.status.success() {
        let stderr = String::from_utf8_lossy(&umount_output.stderr);
        FlashMessage::error(format!("Failed to unmount device: {}", stderr)).send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let close_output = Command::new("sudo").arg("cryptsetup").arg("luksClose").arg(&app_state.config.mapper_name).output().await.unwrap();
    if !close_output.status.success() {
        let stderr = String::from_utf8_lossy(&close_output.stderr);
        FlashMessage::error(format!("Failed to lock device: {}", stderr)).send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    *app_state.is_mounted.lock().unwrap() = false;
    FlashMessage::info("Device unmounted and locked successfully!").send();
    HttpResponse::Found().insert_header((header::LOCATION, "/")).finish()
}

async fn preview_file(app_state: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let file_path = base_path.join(path.as_str());
    if !file_path.starts_with(&base_path) { return HttpResponse::Forbidden().body("Access denied."); }
    match fs::read(&file_path).await {
        Ok(content) => {
            let mime_type = from_path(&file_path).first_or_octet_stream();
            HttpResponse::Ok().content_type(mime_type.as_ref()).body(content)
        }
        Err(e) => {
            log::error!("Failed to read file for preview {:?}: {}", file_path, e);
            HttpResponse::NotFound().body("File not found.")
        }
    }
}

async fn download_file(app_state: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let file_path = base_path.join(path.as_str());
    if !file_path.starts_with(&base_path) { return HttpResponse::Forbidden().body("Access denied."); }
    let filename = file_path.file_name().unwrap_or_default().to_string_lossy();
    match fs::read(&file_path).await {
        Ok(content) => {
            HttpResponse::Ok().content_type("application/octet-stream")
                .insert_header((header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", filename)))
                .body(content)
        }
        Err(e) => {
            log::error!("Failed to read file for download {:?}: {}", file_path, e);
            HttpResponse::NotFound().body("File not found.")
        }
    }
}

async fn create_folder(app_state: web::Data<AppState>, form: web::Form<CreateFolderRequest>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let current_path = base_path.join(&form.current_path);
    if !current_path.starts_with(&base_path) {
        FlashMessage::error("Invalid path.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let new_folder_path = current_path.join(&form.folder_name);
    match fs::create_dir(new_folder_path).await {
        Ok(_) => FlashMessage::success("Folder created successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to create folder: {}", e)).send(),
    }
    HttpResponse::Found().insert_header((header::LOCATION, format!("/?path={}", form.current_path))).finish()
}

async fn upload_files(
    session: Session,
    app_state: web::Data<AppState>, 
    MultipartForm(form): MultipartForm<UploadForm>
) -> impl Responder {
    // Check authentication
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => {
            FlashMessage::error("Please log in to upload files.").send();
            return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish();
        }
    };
    
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let current_path = base_path.join(form.current_path.as_str());
    
    if !current_path.starts_with(&base_path) {
        FlashMessage::error("Invalid path.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    
    // Check if the mount point is accessible
    if !current_path.exists() {
        FlashMessage::error("Upload destination not available. Please unlock and mount your LUKS device first.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    
    // Check write permission
    let user_id = _user.id;
    let rel_path = form.current_path.as_str();
    match check_user_permission(&app_state.db, user_id, rel_path, "write").await {
        Ok(true) => {},
        Ok(false) => {
            FlashMessage::error("You do not have permission to upload files here.").send();
            return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
        },
        Err(e) => {
            log::error!("Permission check failed: {}", e);
            FlashMessage::error("Permission check failed.").send();
            return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
        }
    }

    let mut uploaded_count = 0;
    let mut errors = Vec::new();
    
    for temp_file in form.files {
        if let Some(filename) = temp_file.file_name {
            let dest_path = current_path.join(&filename);
            // Use copy instead of persist to avoid cross-device link errors
            let temp_path = temp_file.file.path();
            match tokio::fs::copy(&temp_path, &dest_path).await {
                Ok(_) => {
                    uploaded_count += 1;
                    log::info!("Successfully uploaded file: {}", filename);
                },
                Err(e) => {
                    let error_msg = format!("Failed to upload {}: {}", filename, e);
                    log::error!("{}", error_msg);
                    errors.push(error_msg);
                }
            }
            // Clean up temp file
            let _ = tokio::fs::remove_file(&temp_path).await;
        }
    }
    
    if uploaded_count > 0 {
        FlashMessage::success(format!("Successfully uploaded {} file(s).", uploaded_count)).send();
    }
    if !errors.is_empty() {
        FlashMessage::error(errors.join("; ")).send();
    }
    
    HttpResponse::Found().insert_header((header::LOCATION, format!("/?path={}", form.current_path.as_str()))).finish()
}
async fn rename_item(app_state: web::Data<AppState>, form: web::Form<RenameRequest>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let current_path = base_path.join(&form.current_path);
    if !current_path.starts_with(&base_path) {
        FlashMessage::error("Invalid path.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let old_path = current_path.join(&form.old_name);
    let new_path = current_path.join(&form.new_name);
    match fs::rename(old_path, new_path).await {
        Ok(_) => FlashMessage::success("Item renamed successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to rename item: {}", e)).send(),
    }
    HttpResponse::Found().insert_header((header::LOCATION, format!("/?path={}", form.current_path))).finish()
}

async fn delete_item(app_state: web::Data<AppState>, form: web::Form<DeleteRequest>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let current_path = base_path.join(&form.current_path);
    if !current_path.starts_with(&base_path) {
        FlashMessage::error("Invalid path.").send();
        return HttpResponse::Found().insert_header((header::LOCATION, "/")).finish();
    }
    let item_path = current_path.join(&form.item_name);
    let result = if item_path.is_dir() { fs::remove_dir_all(item_path).await } else { fs::remove_file(item_path).await };
    match result {
        Ok(_) => FlashMessage::success("Item deleted successfully.").send(),
        Err(e) => FlashMessage::error(format!("Failed to delete item: {}", e)).send(),
    }
    HttpResponse::Found().insert_header((header::LOCATION, format!("/?path={}", form.current_path))).finish()
}

// JSON endpoint for deleting items (used by frontend for multiple deletions)
async fn delete_item_json(
    session: Session,
    app_state: web::Data<AppState>, 
    req: web::Json<DeleteRequest>
) -> impl Responder {
    // Check authentication
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "Please log in to delete files."
            }));
        }
    };
    
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let current_path = base_path.join(&req.current_path);
    
    if !current_path.starts_with(&base_path) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invalid path."
        }));
    }
    
    let item_path = current_path.join(&req.item_name);
    
    // Security check: ensure we're not trying to delete outside the mount point
    if !item_path.starts_with(&base_path) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invalid file path."
        }));
    }
    
    // Check delete permission
    let user_id = _user.id;
    let rel_path = format!("{}/{}", req.current_path, req.item_name);
    match check_user_permission(&app_state.db, user_id, &rel_path, "delete").await {
        Ok(true) => {},
        Ok(false) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "You do not have permission to delete this file."
            }));
        },
        Err(e) => {
            log::error!("Permission check failed: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": "Permission check failed."
            }));
        }
    }

    let result = if item_path.is_dir() { 
        tokio::fs::remove_dir_all(&item_path).await 
    } else { 
        tokio::fs::remove_file(&item_path).await 
    };
    
    match result {
        Ok(_) => {
            log::info!("Successfully deleted: {}", item_path.display());
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Deleted {}", req.item_name)
            }))
        },
        Err(e) => {
            log::error!("Failed to delete {}: {}", item_path.display(), e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to delete {}: {}", req.item_name, e)
            }))
        }
    }
}

// Copy files/folders
async fn copy_items(app_state: web::Data<AppState>, req: web::Json<CopyRequest>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let dest_path = base_path.join(&req.destination_path);
    
    if !dest_path.starts_with(&base_path) || !dest_path.is_dir() {
        return HttpResponse::BadRequest().json("Invalid destination path.");
    }
    
    let mut results = Vec::new();
    
    for source_rel_path in &req.source_paths {
        let source_path = base_path.join(source_rel_path);
        if !source_path.starts_with(&base_path) {
            results.push(format!("Invalid source path: {}", source_rel_path));
            continue;
        }
        
        let file_name = source_path.file_name().unwrap().to_string_lossy();
        let dest_file_path = dest_path.join(file_name.as_ref());
        
        let result = if source_path.is_dir() {
            Command::new("cp")
                .arg("-r")
                .arg(&source_path)
                .arg(&dest_file_path)
                .output()
                .await
        } else {
            Command::new("cp")
                .arg(&source_path)
                .arg(&dest_file_path)
                .output()
                .await
        };
        
        match result {
            Ok(output) if output.status.success() => {
                results.push(format!("Copied: {}", file_name));
            },
            Ok(output) => {
                results.push(format!("Failed to copy {}: {}", file_name, String::from_utf8_lossy(&output.stderr)));
            },
            Err(e) => {
                results.push(format!("Failed to copy {}: {}", file_name, e));
            }
        }
    }
    
    HttpResponse::Ok().json(results)
}

// Move files/folders
async fn move_items(app_state: web::Data<AppState>, req: web::Json<MoveRequest>) -> impl Responder {
    let base_path = PathBuf::from(&app_state.config.mount_point);
    let dest_path = base_path.join(&req.destination_path);
    
    if !dest_path.starts_with(&base_path) || !dest_path.is_dir() {
        return HttpResponse::BadRequest().json("Invalid destination path.");
    }
    
    let mut results = Vec::new();
    
    for source_rel_path in &req.source_paths {
        let source_path = base_path.join(source_rel_path);
        if !source_path.starts_with(&base_path) {
            results.push(format!("Invalid source path: {}", source_rel_path));
            continue;
        }
        
        let file_name = source_path.file_name().unwrap().to_string_lossy();
        let dest_file_path = dest_path.join(file_name.as_ref());
        
        let result = fs::rename(&source_path, &dest_file_path).await;
        
        match result {
            Ok(_) => results.push(format!("Moved: {}", file_name)),
            Err(e) => results.push(format!("Failed to move {}: {}", file_name, e)),
        }
    }
    
    HttpResponse::Ok().json(results)
}


// --- 5. Main Function ---
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:luks_manager.db".to_string());
    let db_pool = SqlitePool::connect(&database_url).await.expect("Failed to connect to database");
    sqlx::migrate!("./migrations").run(&db_pool).await.expect("Failed to run database migrations");
    
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&db_pool).await.unwrap_or(0);
    if user_count == 0 {
        log::info!("No users found in database. Creating default admin user...");
        let admin_pass = "password";
        let hashed_password = hash_password(admin_pass).expect("Failed to hash password");
        sqlx::query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
            .bind("admin").bind(hashed_password).bind("admin").execute(&db_pool).await
            .expect("Failed to create default admin user");
        log::info!("Default admin user created with password: '{}'", admin_pass);
    }

    let config = Config::from_env();
    let initial_mount_status = check_if_mounted(&config.mount_point).await;

    let key: String = thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
    let secret_key = actix_web::cookie::Key::from(key.as_bytes());

    let tera = Tera::new("templates/**/*.html").expect("Failed to parse templates");

    // Initialize CCTV Manager
    let cctv_python_path = std::env::var("CCTV_PYTHON_PATH")
        .unwrap_or_else(|_| "../Home_CCTV_AI".to_string());
    let cctv_api_port: u16 = std::env::var("CCTV_API_PORT")
        .unwrap_or_else(|_| "8082".to_string())
        .parse()
        .expect("Invalid CCTV_API_PORT");
    
    let cctv_manager = cctv_manager::CctvManager::new(&cctv_python_path, cctv_api_port);
    
    let app_state = AppState {
        is_mounted: Arc::new(Mutex::new(initial_mount_status)),
        config,
        db: db_pool,
        tera: tera,
        cctv_manager: Arc::new(Mutex::new(cctv_manager)),
    };

    log::info!("Starting server at http://127.0.0.1:8081");

    HttpServer::new(move || {
        let session_mw = SessionMiddleware::new(CookieSessionStore::default(), secret_key.clone());
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(session_mw)
            .wrap(FlashMessagesFramework::builder(
                actix_web_flash_messages::storage::CookieMessageStore::builder(secret_key.clone()).build()
            ).build())
            .route("/", web::get().to(show_dashboard))
            .route("/login", web::get().to(show_login_form))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/unlock", web::post().to(unlock_drive))
            .route("/lock", web::post().to(lock_drive))
            .route("/preview/{path:.*}", web::get().to(preview_file))
            .route("/download/{path:.*}", web::get().to(download_file))
            .route("/create_folder", web::post().to(create_folder))
            .route("/upload", web::post().to(upload_files))
            .route("/rename", web::post().to(rename_item))
            .route("/delete", web::post().to(delete_item))
            .route("/delete_json", web::post().to(delete_item_json))
            .route("/copy", web::post().to(copy_items))
            .route("/move", web::post().to(move_items))
            .route("/admin/users", web::get().to(show_admin_users))
            .route("/admin/users/add", web::get().to(show_add_user_form))
            .route("/admin/users/add", web::post().to(add_user))
            .route("/admin/users/delete", web::post().to(delete_user))
            .route("/admin/users/bulk-delete", web::post().to(bulk_delete_users))
            .route("/admin/users/edit/{user_id}", web::get().to(show_edit_user_form))
            .route("/admin/users/edit/{user_id}", web::post().to(edit_user))
            .route("/admin/permissions", web::get().to(show_admin_permissions))
            .route("/admin/permissions/add", web::post().to(add_permission))
            .route("/admin/permissions/delete", web::post().to(delete_permission))
            .route("/admin/api/server-health", web::get().to(server_health_api))
            .route("/admin/server-health", web::get().to(show_server_health_dashboard))
            .route("/cctv", web::get().to(show_cctv_dashboard))
            // CCTV Management Routes (Phase 2)
            .route("/cctv/status", web::get().to(cctv_status))
            .route("/cctv/start", web::post().to(cctv_start))
            .route("/cctv/stop", web::post().to(cctv_stop))
            .route("/cctv/cameras", web::get().to(cctv_cameras))
            .route("/cctv/stream/{camera_id}", web::get().to(cctv_stream))
            .route("/cctv/recordings", web::get().to(cctv_recordings))
            .route("/cctv/recording/{filename}", web::get().to(cctv_recording))
            .service(Files::new("/static", "./static").show_files_listing())
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}

// Simple bulk delete endpoint
async fn bulk_delete_users(
    session: Session,
    app_state: web::Data<AppState>,
    form: web::Json<serde_json::Value>,
) -> impl Responder {
    // Check if user is logged in and is admin
    let current_user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "success": false,
            "message": "Authentication required"
        })),
    };

    if current_user.role != "admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "success": false,
            "message": "Admin privileges required."
        }));
    }

    let user_ids = match form.get("user_ids") {
        Some(ids) => match ids.as_array() {
            Some(arr) => arr.iter().filter_map(|v| v.as_i64()).collect::<Vec<_>>(),
            None => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "success": false,
                    "message": "Invalid user_ids format."
                }));
            }
        },
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "message": "Missing user_ids."
            }));
        }
    };

    let mut deleted_count = 0;
    let mut errors = Vec::new();

    for user_id in &user_ids {
        // Prevent deleting current user
        if *user_id == current_user.id {
            errors.push(format!("Cannot delete current user (ID: {})", user_id));
            continue;
        }

        // Get user details
        let user = match sqlx::query_as::<_, User>("SELECT id, username, password_hash, role, last_login FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&app_state.db)
            .await {
                Ok(Some(user)) => user,
                Ok(None) => {
                    errors.push(format!("User ID {} not found", user_id));
                    continue;
                },
                Err(e) => {
                    errors.push(format!("Database error for user ID {}: {}", user_id, e));
                    continue;
                }
            };

        // If deleting an admin, check if there are other admins
        if user.role == "admin" {
            let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                .fetch_one(&app_state.db)
                .await
                .unwrap_or(0);
            if admin_count <= 1 {
                errors.push(format!("Cannot delete the last admin user: {}", user.username));
                continue;
            }
        }

        // Delete the user
        match sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id)
            .execute(&app_state.db)
            .await {
                Ok(_) => {
                    deleted_count += 1;
                    log::info!("User {} (ID: {}) deleted by admin {}", user.username, user_id, current_user.username);
                },
                Err(e) => {
                    errors.push(format!("Failed to delete user ID {}: {}", user_id, e));
                }
            }
    }

    let response = if deleted_count > 0 {
        let message = if errors.is_empty() {
            format!("Successfully deleted {} user(s)", deleted_count)
        } else {
            format!("Deleted {} user(s). Errors: {}", deleted_count, errors.join(", "))
        };
        serde_json::json!({
            "success": true,
            "message": message,
            "deleted_count": deleted_count,
            "errors": errors
        })
    } else {
        serde_json::json!({
            "success": false,
            "message": format!("No users were deleted. Errors: {}", errors.join(", ")),
            "errors": errors
        })
    };

    HttpResponse::Ok().json(response)
}

async fn server_health_api(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    // Only allow admin
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) if user.role == "admin" => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Unauthorized"})),
    };

    let mut sys = System::new_all();
    sys.refresh_all();
    let uptime = System::uptime();
    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();
    
    // Get CPU usage
    let cpu_usage = sys.global_cpu_usage();
    
    // Get disk usage
    let disks: Vec<serde_json::Value> = vec![];
    
    let now = chrono::Utc::now().to_rfc3339();

    HttpResponse::Ok().json(serde_json::json!({
        "uptime": uptime,
        "server_time": now,
        "memory": {
            "total": total_memory,
            "used": used_memory,
            "total_swap": total_swap,
            "used_swap": used_swap
        },
        "cpu_usage": cpu_usage,
        "disks": disks
    }))
}


// Handler to render the server health dashboard page
async fn show_server_health_dashboard(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) if user.role == "admin" => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };

    let mut context = Context::new();
    context.insert("current_page", "server_health");
    
    match app_state.tera.render("admin_server_health.html", &context) {
        Ok(rendered) => HttpResponse::Ok().content_type("text/html").body(rendered),
        Err(err) => {
            log::error!("Template error: {}", err);
            HttpResponse::InternalServerError().body("Template error")
        }
    }
}

// ============================================================================
// CCTV Management Handlers (Phase 2)
// ============================================================================

// Get CCTV system status
async fn cctv_status(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication required"
        })),
    };

    let cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.health_check().await {
        Ok(is_healthy) => {
            if is_healthy {
                match cctv_manager.get_system_status().await {
                    Ok(status) => HttpResponse::Ok().json(status),
                    Err(e) => {
                        log::error!("Failed to get CCTV status: {}", e);
                        HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to get system status"
                        }))
                    }
                }
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "running": false,
                    "message": "CCTV system is not running"
                }))
            }
        }
        Err(e) => {
            log::error!("CCTV health check failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Health check failed"
            }))
        }
    }
}

// Start CCTV system
async fn cctv_start(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let user = match session.get::<User>("user") {
        Ok(Some(user)) if user.role == "admin" => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Admin authentication required"
        })),
    };

    log::info!("User {} starting CCTV system", user.username);
    
    let mut cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.start_api_server().await {
        Ok(_) => {
            log::info!("CCTV system started successfully");
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "CCTV system started successfully"
            }))
        }
        Err(e) => {
            log::error!("Failed to start CCTV system: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to start CCTV system: {}", e)
            }))
        }
    }
}

// Stop CCTV system
async fn cctv_stop(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let user = match session.get::<User>("user") {
        Ok(Some(user)) if user.role == "admin" => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Admin authentication required"
        })),
    };

    log::info!("User {} stopping CCTV system", user.username);
    
    let mut cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.stop_api_server().await {
        Ok(_) => {
            log::info!("CCTV system stopped successfully");
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "CCTV system stopped successfully"
            }))
        }
        Err(e) => {
            log::error!("Failed to stop CCTV system: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to stop CCTV system: {}", e)
            }))
        }
    }
}

// List cameras
async fn cctv_cameras(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication required"
        })),
    };

    let cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.list_cameras().await {
        Ok(cameras) => HttpResponse::Ok().json(cameras),
        Err(e) => {
            log::error!("Failed to list cameras: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list cameras"
            }))
        }
    }
}

// Proxy camera stream
async fn cctv_stream(
    path: web::Path<String>, 
    session: Session, 
    app_state: web::Data<AppState>
) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().finish(),
    };

    let camera_id = path.into_inner();
    let cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.get_camera_stream_url(&camera_id).await {
        Ok(stream_url) => {
            // Proxy the stream (simplified - in production you might want more sophisticated streaming)
            HttpResponse::Found()
                .insert_header((header::LOCATION, stream_url))
                .finish()
        }
        Err(e) => {
            log::error!("Failed to get stream URL for camera {}: {}", camera_id, e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

// List recordings
async fn cctv_recordings(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Authentication required"
        })),
    };

    let cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.list_recordings().await {
        Ok(recordings) => HttpResponse::Ok().json(recordings),
        Err(e) => {
            log::error!("Failed to list recordings: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list recordings"
            }))
        }
    }
}

// Get specific recording
async fn cctv_recording(
    path: web::Path<String>, 
    session: Session, 
    app_state: web::Data<AppState>
) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Unauthorized().finish(),
    };

    let filename = path.into_inner();
    let cctv_manager = app_state.cctv_manager.lock().unwrap();
    
    match cctv_manager.get_recording_url(&filename).await {
        Ok(recording_url) => {
            // Proxy the recording download
            HttpResponse::Found()
                .insert_header((header::LOCATION, recording_url))
                .finish()
        }
        Err(e) => {
            log::error!("Failed to get recording URL for {}: {}", filename, e);
            HttpResponse::NotFound().finish()
        }
    }
}

// CCTV Dashboard Handler
async fn show_cctv_dashboard(session: Session, app_state: web::Data<AppState>) -> impl Responder {
    let _user = match session.get::<User>("user") {
        Ok(Some(user)) => user,
        _ => return HttpResponse::Found().insert_header((header::LOCATION, "/login")).finish(),
    };

    let mut context = Context::new();
    context.insert("current_page", "cctv");
    
    match app_state.tera.render("cctv_dashboard.html", &context) {
        Ok(rendered) => HttpResponse::Ok().content_type("text/html").body(rendered),
        Err(err) => {
            log::error!("Template error: {}", err);
            HttpResponse::InternalServerError().body("Template error")
        }
    }
}
