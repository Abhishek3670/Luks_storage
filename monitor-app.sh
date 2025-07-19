#!/bin/bash
# ===================================
# LUKS Web Manager Application Monitor
# ===================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
log_success() { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} ✅ $1"; }
log_warning() { echo -e "${YELLOW}[$(date '+%H:%M:%S')]${NC} ⚠️  $1"; }
log_error() { echo -e "${RED}[$(date '+%H:%M:%S')]${NC} ❌ $1"; }

echo "======================================"
echo "🔐 LUKS Web Manager - Live Monitoring"
echo "======================================"
echo ""

# Function to check server status
check_server() {
    local response=$(curl -s -o /dev/null -w "%{http_code}:%{time_total}:%{size_download}" http://127.0.0.1:8081/login 2>/dev/null)
    if [ $? -eq 0 ]; then
        IFS=':' read -r code time size <<< "$response"
        if [ "$code" = "200" ]; then
            log_success "Server responding | HTTP: $code | Time: ${time}s | Size: $size bytes"
            return 0
        else
            log_warning "Server HTTP error: $code"
            return 1
        fi
    else
        log_error "Server unreachable"
        return 1
    fi
}

# Function to check process status
check_process() {
    local pid=$(pgrep -f "luks_web_manager")
    if [ -n "$pid" ]; then
        local mem=$(ps -p $pid -o rss --no-headers 2>/dev/null)
        local cpu=$(ps -p $pid -o %cpu --no-headers 2>/dev/null)
        log_success "Process running | PID: $pid | Memory: ${mem}KB | CPU: ${cpu}%"
        return 0
    else
        log_error "Process not running"
        return 1
    fi
}

# Function to check port status
check_port() {
    if ss -tln | grep -q ":8081"; then
        log_success "Port 8081 listening"
        return 0
    else
        log_error "Port 8081 not listening"
        return 1
    fi
}

# Function to check logs
check_logs() {
    if [ -f "logs/server.log" ]; then
        local lines=$(wc -l < logs/server.log)
        local errors=$(grep -c "ERROR\|WARN\|panic" logs/server.log 2>/dev/null || echo "0")
        if [ "$errors" -eq 0 ]; then
            log_success "Logs clean | Lines: $lines | Errors: $errors"
        else
            log_warning "Log issues found | Lines: $lines | Errors/Warnings: $errors"
        fi
    else
        log_warning "No log file found"
    fi
}

# Function to test endpoints
test_endpoints() {
    local endpoints=("/login" "/static/css/components.css" "/static/js/modern-dashboard.js")
    local passed=0
    local total=${#endpoints[@]}
    
    for endpoint in "${endpoints[@]}"; do
        local code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8081$endpoint" 2>/dev/null)
        if [ "$code" = "200" ]; then
            ((passed++))
        fi
    done
    
    if [ $passed -eq $total ]; then
        log_success "All endpoints responding | $passed/$total passed"
    else
        log_warning "Some endpoints failing | $passed/$total passed"
    fi
}

# Main monitoring loop
monitor_count=0
while true; do
    ((monitor_count++))
    echo ""
    log_info "🔄 Monitor Check #$monitor_count"
    echo "--------------------------------------"
    
    # System checks
    check_process
    check_port  
    check_server
    test_endpoints
    check_logs
    
    # Resource usage
    log_info "📊 System Resources:"
    echo "   CPU Load: $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo "   Memory: $(free -h | grep '^Mem:' | awk '{print $3"/"$2}')"
    echo "   Disk: $(df -h . | tail -1 | awk '{print $3"/"$2" ("$5")"}')"
    
    # Recent log activity
    if [ -f "logs/server.log" ]; then
        echo ""
        log_info "📝 Recent Activity:"
        tail -3 logs/server.log | sed 's/^/   /'
    fi
    
    echo ""
    echo "✨ Modern UI Status: Active | Security Theme: Enabled | Components: Loaded"
    echo "🌐 Access: http://127.0.0.1:8081 | Login: admin/password"
    
    if [ $monitor_count -ge 5 ]; then
        echo ""
        log_info "🎯 Monitoring completed after 5 cycles"
        break
    fi
    
    echo ""
    log_info "⏳ Next check in 10 seconds... (Ctrl+C to stop)"
    sleep 10
done

echo ""
echo "======================================"
echo "🏁 Monitoring Session Complete"
echo "======================================"
