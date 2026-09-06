# Code.ak — Integration Generator

<p align="center">
  <img src="assets/codeak-logo.png" width="160" alt="Code.ak">
</p>
<p align="center">HACK.GENESIS 2026 · Генератор интеграций с платёжными провайдерами</p>

Принимает **OpenAPI** и создаёт **Ruby-сервис для `Provider::BaseService`**: вместе с инструкцией подключения, fixtures, результатами анализа и HTML-отчётом.

`OpenAPI → анализ и сопоставления → явные уточнения → проверка → генерация`

Работает локально, без обращений к API провайдера. Нейросети в runtime не используются.

## Проверка экспертами

Команды выполняются из корня репозитория. Нужны Ruby с OpenSSL и Bundler; финальная проверка выполнена на Ruby 4.0.6 и Bundler 4.0.16. Все команды ниже записаны в одну строку и подходят для PowerShell. Многострочные команды в PowerShell удобнее выполнять одной строкой.

### 1. Установить зависимости

```sh
bundle install
```

### 2. Посмотреть CLI

```sh
bundle exec ruby bin/integrate --help
```

### 3. Проверить неоднозначности OpenAPI

```sh
bundle exec ruby bin/integrate --spec provider_api.yaml --provider novapay --analyze --strict
```

**Ожидаемый exit code: 2.** Это штатный отказ строгой проверки. NovaPay описывает HMAC, но не уточняет подписываемые данные и кодировку подписи. CLI покажет `unresolved_signature`; файлы не создаются.

### 4. Посмотреть подробный анализ

```sh
bundle exec ruby bin/integrate --spec provider_api.yaml --provider novapay --analyze --explain
```

В выводе — пять методов и их роли, схемы авторизации, правила суммы и условных полей, настройки подписи, источники выводов и диагностика. Здесь ожидается exit code 0: без `--strict` анализ показывает нерешённые вопросы, но не завершает команду кодом 2.

### 5. Сгенерировать NovaPay

Уточнения подготовлены в [novapay.overrides.yml](examples/novapay.overrides.yml).

```sh
bundle exec ruby bin/integrate --spec provider_api.yaml --provider novapay --overrides examples/novapay.overrides.yml --output output/novapay --strict
```

Ожидается exit code 0 и семь файлов в `output/novapay`. Обычный CLI перечисляет первые три; полный список виден с `--explain`.

### 6. Проверить Ruby

```sh
ruby -c output/novapay/novapay_service.rb
```

Ожидается `Syntax OK`.

### 7. Открыть результат

Откройте локальный `output/novapay/generation_report.html` в браузере. Начните с методов, полей выплаты и webhook. Порядок подключения сервиса находится рядом, в `INTEGRATION.md`.

Папка `output/` создаётся при запуске и не хранится в репозитории.

## CLI

| Параметр | Назначение |
| --- | --- |
| `--spec PATH` | Обязательный путь к локальной OpenAPI в YAML или JSON. |
| `--provider NAME` | Имя файла сервиса, Ruby-класса и префикса ENV. Например, `novapay` → `novapay_service.rb`, `Provider::NovapayService`, `NOVAPAY_BASE_URL`. Без параметра имя выводится из `info.title`. |
| `--overrides PATH` | YAML с явными уточнениями ролей, полей, суммы, статусов и других настроек. |
| `--output PATH` | Каталог результата; по умолчанию `output/<provider>`. Можно задать абсолютный путь. Сегменты `..` запрещены. |
| `--analyze` | Выполнить анализ и валидацию без записи файлов. |
| `--strict` | При оставшихся blocking errors завершиться с кодом 2 до генерации. Используйте для получения готовой интеграции. |
| `--explain` | Показать operationId, role и confidence, схемы auth, правила, provenance и все diagnostics; при генерации — все созданные файлы. |
| `--lang ruby` | Явно выбрать Ruby. Другие языки не поддерживаются. |
| `--help` / `-h` | Показать справку и завершиться. |

Обычный вывод содержит API, методы, авторизацию, единицы суммы и число разделов overrides. При strict failure blocking diagnostics выводятся и без `--explain`. Без `--strict` нерешённые диагностические ошибки сами по себе не останавливают генерацию.

| Exit code | Значение |
| --- | --- |
| `0` | Команда выполнена; без `--strict` это не означает отсутствие замечаний. |
| `1` | Ошибка аргументов, чтения или проверки spec/overrides либо записи результата. |
| `2` | Строгая валидация не пройдена; генерация не выполнена. |

## Что создаётся

Основной результат — Ruby-сервис. HTML-отчёт представляет те же сведения в удобном для чтения виде.

| Файл | Содержимое |
| --- | --- |
| `<provider>_service.rb` | Сервис для `Provider::BaseService` с runtime-конфигурацией и запросами к провайдеру. |
| `INTEGRATION.md` | Подключение, методы, поля, статусы, webhook и примеры вызова. |
| `fixtures.json` | Примеры запросов, ответов и callback; при настроенной подписи — тестовый вектор HMAC. |
| `analysis.json` | Полный результат анализа: схемы, сопоставления, источники и диагностика. |
| `warnings.json` | Диагностические сообщения, включая информационные и подтверждённые через overrides. |
| `generation_report.html` | Локальная страница для просмотра интеграции. |
| `manifest.json` | SHA-256 шести остальных файлов для проверки повторной генерации. |

Для одинаковых spec, provider и overrides результат воспроизводим побайтово. Если generated файл изменён вручную, генератор откажется перезаписывать его. Сохраните свои изменения и выберите новый каталог результата. Manifest проверяет целостность файлов; это не шифрование.

## Как это работает

```text
OpenAPI → SpecLoader → Analyzer → IR → Overrides → Validator → Generator
```

| Шаг | Что делает |
| --- | --- |
| SpecLoader | Читает YAML/JSON, проверяет структуру и разрешает внутренние и допустимые локальные `$ref`. |
| Analyzer | Находит методы, роли, поля, авторизацию и признаки бизнес-правил. |
| IR | Хранит промежуточное представление API, сопоставления, источники и диагностику. |
| Overrides | Добавляет явные уточнения к результату анализа. |
| Validator | Проверяет полноту и совместимость настроек; `--strict` останавливает генерацию при blocking errors. |
| Generator | Создаёт семь файлов, проверяет синтаксис Ruby и учитывает manifest. |

### Что определяется автоматически, а что требует уточнения

Структура OpenAPI задаёт endpoints, HTTP methods, request/response fields и auth. Названия полей и описания помогают определить роли операций, mappings, статусы, HTTP errors, единицы суммы, webhook/HMAC, idempotency и условно обязательные поля. Источник и confidence каждого вывода доступны в `--explain` и `analysis.json`.

Однако статус `READY` не всегда означает `approved`, integer amount не объясняет, рубли это или копейки, а описание HMAC может не содержать hex/base64. Неоднозначные сведения требуют явных overrides. Они уточняют бизнес-смысл, но не отключают структурную проверку OpenAPI.

Формат и примеры: [docs/OVERRIDES.md](docs/OVERRIDES.md).

### Логическое действие и HTTP method

`request_method` — действие host-приложения. В DuoPay `card_payout` выбирает operationId `createCardPayout`, а `sbp_payout` — `createSbpPayout`. HTTP method `POST` и путь каждого запроса берутся из OpenAPI. Если роль `create` соответствует нескольким endpoints, вызов по одной роли не выбирает первый молча.

## Четыре примера провайдеров

Количество провайдеров не ограничено именами или специальными ветками в ядре. Новый API с уже поддерживаемыми механизмами проходит через тот же pipeline. Неподдерживаемый механизм должен дать ошибку или diagnostic и strict failure; поддержка любого OpenAPI не заявляется.

| Провайдер | Что показывает |
| --- | --- |
| [NovaPay](provider_api.yaml) | Официальная spec: API key в header, HMAC hex, SBP/card, cancel и balance. Команды — в проверке экспертами выше. |
| [RiverPay](examples/providers/riverpay.yaml) | Bearer, вложенные поля, major units ×1 и HMAC Base64. |
| [CardFlow](examples/providers/cardflow.yaml) | API key в query, другие имена полей и статусов, minor units ×100, без webhook. |
| [DuoPay](examples/providers/duopay.yaml) | Два create endpoint с выбором через operationId. |

RiverPay, CardFlow и DuoPay — синтетические примеры. Для каждого есть готовые overrides.

### RiverPay

```sh
bundle exec ruby bin/integrate --spec examples/providers/riverpay.yaml --provider riverpay --overrides examples/providers/riverpay.overrides.yml --output output/riverpay --strict
ruby -c output/riverpay/riverpay_service.rb
```

### CardFlow

Без overrides ожидается exit code 2: роли, сопоставления и смысл статусов требуют уточнения.

```sh
bundle exec ruby bin/integrate --spec examples/providers/cardflow.yaml --provider cardflow --analyze --strict
```

С overrides ожидается успешная генерация:

```sh
bundle exec ruby bin/integrate --spec examples/providers/cardflow.yaml --provider cardflow --overrides examples/providers/cardflow.overrides.yml --output output/cardflow --strict
ruby -c output/cardflow/cardflow_service.rb
```

### DuoPay

```sh
bundle exec ruby bin/integrate --spec examples/providers/duopay.yaml --provider duopay --overrides examples/providers/duopay.overrides.yml --output output/duopay --strict
ruby -c output/duopay/duopay_service.rb
```

Для всех четырёх сервисов ожидается `Syntax OK`. HTML-отчёты лежат в соответствующих папках `output/<provider>/generation_report.html`.

## Подключение к приложению

Приложение предоставляет `Provider::BaseService`, HTTP-клиент и credentials. Generated `INTEGRATION.md` содержит пример создания сервиса и вызова его методов. Генератор сам не отправляет выплаты.

После create сервис возвращает ID провайдера; приложение сохраняет его в `operation.provider_operation_key` для status/cancel. Balance сохраняет поля ответа провайдера, если явные response mappings не задают преобразование.

Webhook проходит через HTTP-обработчик приложения: сначала проверка подписи по исходному `raw_body`, затем разбор JSON и `process_callback`. Повторно сериализованный JSON не заменяет исходные байты. Gateway выбирает приложение; его значение нельзя определить из OpenAPI.

## Проверка качества

Перед финальной версией решение проверено не только на генерацию файлов, но и на поведение сгенерированных сервисов.

Проверено:

- все 5 методов официального NovaPay: create, status, cancel, balance и webhook;
- генерация и работа NovaPay, RiverPay, CardFlow и DuoPay;
- разные варианты авторизации: API Key, Bearer и Basic;
- суммы в основных и минимальных единицах без скрытого округления;
- HMAC-SHA256 webhook в hex и Base64;
- несколько create-endpoints с выбором через `operationId`;
- неизвестные статусы, неоднозначные mappings и неподдерживаемые конструкции блокируются `--strict`;
- повторная генерация даёт одинаковый результат;
- изменённые вручную generated-файлы не перезаписываются молча;
- некорректные OpenAPI, большие/глубокие ответы, неверный UTF-8 и другие ошибочные входные данные обрабатываются контролируемо.

Дополнительно решение проверялось на новых синтетических OpenAPI с отличающимися структурами API. Поддерживаемые механизмы генерировались тем же ядром, а неподдерживаемые случаи завершались диагностикой вместо молчаливой генерации неверного сервиса.

## Защита входных данных

- YAML/JSON проверяются на duplicate keys, неверный UTF-8 и превышение лимитов размера, глубины и числа узлов. Ruby-объекты из YAML не десериализуются.
- `$ref` разрешены внутри документа и каталога spec; удалённые ссылки и выход за каталог запрещены.
- HMAC проверяется по raw body через `OpenSSL.fixed_length_secure_compare` после проверки длины. Callback и provider responses имеют ограничения данных.
- Денежные значения обрабатываются через `BigDecimal`; дробное значение для integer target отклоняется без округления. Проверяются headers и base URL.
- Перед записью проверяется Ruby syntax, а manifest защищает ручные изменения. Неподдерживаемые schema/auth/media получают ошибки или blocking diagnostics для `--strict`.

## Границы поддержки

- Основной сценарий — OpenAPI 3.0.x, JSON и `application/*+json`. Корневые request/успешные response schemas должны соответствовать JSON object. Поддержка OpenAPI 3.1 частичная; top-level webhooks не поддерживаются.
- `oneOf/anyOf`, конфликтующий `allOf`, циклические ссылки и другие неподдерживаемые конструкции требуют нормализации spec или отдельного адаптера. Совместимый `allOf` и локальные `$ref` поддерживаются.
- XML и OAuth token acquisition не генерируются. Поддерживаются API key header/query, Bearer и Basic в пределах описанного контракта.
- Реальная сеть провайдера и production host-приложение не проверялись: runtime E2E использует fake host по контракту кейса. Проверки файловых ссылок на Windows включали directory junctions; отдельные file symlinks ограничены правами окружения.
- Хранение секретов, transport timeouts/streaming limits, retry, replay protection и дедупликация callback остаются обязанностями host-приложения.

## Лицензия и команда

Реализация — [MIT](LICENSE). Условия исходных материалов указаны в [NOTICE.md](NOTICE.md).

Разработано [Code.ak](https://codeak.ru).
