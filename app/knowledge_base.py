FIXES = {
    "SQL Injection": "Используйте параметризованные запросы (Prepared Statements). Для PHP – PDO, для Python – SQLAlchemy.",
    "XSS": "Экранируйте вывод (HTML entities). Применяйте Content-Security-Policy.",
    "Command Injection": "Избегайте вызова системных команд с пользовательским вводом. Используйте subprocess.run(shell=False).",
    "SSTI": "Никогда не передавайте пользовательский ввод в шаблонизаторы без строгой фильтрации.",
    "Missing CSP": "Добавьте заголовок Content-Security-Policy со строгими директивами.",
    # ... можно расширить
}
def get_fix(vuln_type):
    return FIXES.get(vuln_type, "Следуйте лучшим практикам OWASP для данного типа уязвимости.")
