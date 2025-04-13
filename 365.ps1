<#
.SYNOPSIS
    Скрипт для блокировки или удаления IP-адресов Microsoft 365 из JSON-файла в Windows Firewall
.DESCRIPTION
    Читает IP-адреса из файла 365.json и создает или удаляет правила блокировки для каждого диапазона
.NOTES
    Требует прав администратора для изменения настроек брандмауэра
#>

param (
    [switch]$Remove
)

# Проверка прав администратора
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Скрипт требует запуска с правами администратора" -ForegroundColor Red
    exit 1
}

# Путь к JSON файлу
$jsonPath = "365.json"

# Проверка существования файла
if (-not (Test-Path $jsonPath)) {
    Write-Host "Файл $jsonPath не найден" -ForegroundColor Red
    exit 1
}

# Чтение JSON файла
try {
    $jsonData = Get-Content $jsonPath -Raw | ConvertFrom-Json
}
catch {
    Write-Host "Ошибка при чтении JSON файла: $_" -ForegroundColor Red
    exit 1
}

# Сбор всех уникальных IP-адресов
$allIPs = @()
foreach ($item in $jsonData) {
    if ($item.ips) {
        $allIPs += $item.ips
    }
}

$uniqueIPs = $allIPs | Select-Object -Unique

if ($uniqueIPs.Count -eq 0) {
    Write-Host "В файле не найдено IP-адресов для блокировки" -ForegroundColor Yellow
    exit 0
}

# Имя группы правил
$ruleGroup = "Microsoft365 Blocklist"

if ($Remove) {
    # Удаление правил блокировки
    $removedCount = 0
    foreach ($ip in $uniqueIPs) {
        $ruleName = "Block Microsoft365 IP $ip"
        
        # Проверяем, существует ли правило
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            try {
                # Удаляем правило
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-Host "Удалено правило для $ip" -ForegroundColor Green
                $removedCount++
            }
            catch {
                Write-Host "Ошибка при удалении правила для $ip : $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Правило для $ip не найдено, пропускаем" -ForegroundColor Yellow
        }
    }

    Write-Host "`nГотово! Удалено $removedCount уникальных IP-адресов/диапазонов из Microsoft 365" -ForegroundColor Cyan
}
else {
    # Создание правил блокировки
    $blockedCount = 0
    foreach ($ip in $uniqueIPs) {
        $ruleName = "Block Microsoft365 IP $ip"
        
        # Проверяем, существует ли уже такое правило
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if (-not $existingRule) {
            try {
                # Создаем правило блокировки
                New-NetFirewallRule -DisplayName $ruleName `
                                   -Direction Outbound `
                                   -RemoteAddress $ip `
                                   -Action Block `
                                   -Group $ruleGroup `
                                   -ErrorAction Stop
                
                Write-Host "Создано правило блокировки для $ip" -ForegroundColor Green
                $blockedCount++
            }
            catch {
                Write-Host "Ошибка при создании правила для $ip : $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Правило для $ip уже существует, пропускаем" -ForegroundColor Yellow
        }
    }

    Write-Host "`nГотово! Заблокировано $blockedCount уникальных IP-адресов/диапазонов из Microsoft 365" -ForegroundColor Cyan
    Write-Host "Все правила объединены в группу: '$ruleGroup'" -ForegroundColor Cyan
    Get-NetFirewallRule -Group "Microsoft365 Blocklist" | Format-Table DisplayName, RemoteAddress
}
