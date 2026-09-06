# Overrides

Уточнения задаются в YAML. Неизвестные ключи, ошибочные типы и ссылки на несуществующие операции, поля или схемы авторизации отклоняются до генерации. YAML aliases и Ruby-объекты запрещены. Ключи сопоставлений, включая HTTP-коды, должны быть строками.

| Ключ | Формат |
| --- | --- |
| operations | operationId → create/status/cancel/webhook/balance/unknown |
| field_mappings | operationId → {target.dot.path: canonical.field}; также имя path/query/header параметра |
| response_mappings | operationId → {canonical.field: target.dot.path} |
| amount | {unit: major/minor, factor: положительное конечное число}; major требует factor 1 |
| required_if | [{field: target.path, when: {field: other.target.path, value: scalar}}] |
| status_mappings | provider status → in_progress/approved/rejected |
| error_mappings | HTTP-код строкой → canonical error name; допустим default |
| signature | algorithm: HMAC-SHA256/none; header: HTTP token; signed_data: raw_body; encoding: hex/base64 |
| auth | securityScheme name → {credential: credential_name}; Basic использует username/password |
| idempotency | operationId → {name: token, in: header/query} |
| request_methods | логическое действие → create/status/cancel/balance, operationId или {operationId: имя} |

Поля интеграции: amount, currency, external_id, provider_operation_id, status, recipient.type, recipient.phone, recipient.bank_code, recipient.bank_name, recipient.card_number, error.code, error.message, event, payout_id, created_at, completed_at.

```yaml
operations:
  dispatchTransfer: create
field_mappings:
  dispatchTransfer:
    funds.total: amount
    reference: external_id
response_mappings:
  dispatchTransfer:
    provider_operation_id: ticket
    status: phase
amount: {unit: major, factor: 1}
status_mappings: {queued: in_progress, settled: approved, declined: rejected}
signature:
  algorithm: HMAC-SHA256
  header: X-Callback-Digest
  signed_data: raw_body
  encoding: base64
error_mappings:
  '429': rate_limit
request_methods: {card_transfer: create}
```

Если у роли несколько endpoints, укажите каждый через отдельный logical request_method:

```yaml
request_methods:
  card_payout: createCardPayout
  sbp_payout: createSbpPayout
```

Строки `create/status/cancel/balance` по-прежнему выбирают роль и требуют ровно один endpoint при вызове. Для operationId, совпадающего с именем роли, используйте `{operationId: create}`. Несуществующие операции, `unknown` и webhook выбирать для исходящего запроса нельзя. Пример с двумя create-методами: `examples/providers/duopay.yaml` и `duopay.overrides.yml`.

Сопоставления полей и статусов объединяются с результатом анализа. Правило с тем же полем и условием заменяет ранее выведенное. Исходные варианты и источники остаются в `analysis.json`, а уточнения добавляются отдельными записями.

При неоднозначности сначала выполните `--analyze --explain`, задайте нужные уточнения и повторите `--analyze --strict`. Если схема не поддерживается, исправьте входной OpenAPI: overrides не отключают структурную проверку.
