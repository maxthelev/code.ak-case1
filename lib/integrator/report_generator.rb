# frozen_string_literal: true

require 'json'
require 'cgi/escape'
require 'bigdecimal'
require 'erb'
require 'base64'

module Integrator
  class ReportGenerator
    def initialize(ir)
      @ir = ir
    end

    # шаблон получает обычные строки и экранирует их только при вставке в html
    def html
      directory = File.expand_path('../../templates', __dir__)
      template = File.read(File.join(directory, 'report.html.erb'), encoding: 'UTF-8')
      css = File.read(File.join(directory, 'report.css'), encoding: 'UTF-8')
      logo = Base64.strict_encode64(File.binread(File.expand_path('../../assets/codeak-logo.png', __dir__)))
      ERB.new(template, trim_mode: '-').result_with_hash(data: report_data, css: css, logo: logo, h: method(:escape))
    end

    # заметка использует те же данные что и html но без его разметки
    def integration
      data = report_data
      sections = [
        "# #{escape(data[:title])}",
        "## Подключение\n\n" + (data[:servers].empty? ? '' : md_table(%w[Среда Адрес], data[:servers])) + "\n\n" +
          (data[:auth].empty? ? '' : md_table(['Авторизация', 'Данные авторизации'], data[:auth], technical: [0, 1])) + "\n\n#{data[:connection]}",
        ("## Методы\n\n" + md_table(['Действие', 'Метод API'], data[:methods], technical: [1]) unless data[:methods].empty?),
        ("## Выплата\n\n#{escape(data[:amount])}\n\n" + data[:payments].map { |payment|
          "### #{md_code(payment[:endpoint])}\n\n" + payment[:minima].map { |text| escape(text) }.join("\n") + "\n\n" +
            md_table(['Поле API', 'Поле интеграции', 'Обязательно'], payment[:fields], technical: [0, 1])
        }.join("\n\n") + "\n\n" +
          data[:conditions].map { |text| "- #{escape(text)}" }.join("\n") + "\n\n#{escape(data[:idempotency])}\n\n#{escape(data[:requisites])}" unless data[:payments].empty?),
        ("## Статусы\n\n" + md_table(%w[Провайдер Приложение], data[:statuses], technical: [0, 1]) unless data[:statuses].empty?),
        ("## Ошибки\n\n" + md_table(%w[Метод HTTP Ошибка], data[:errors], technical: [0, 1, 2]) + "\n\n#{data[:failure_codes]}" unless data[:errors].empty?),
        ("## Webhook\n\n" + md_table(%w[Параметр Значение], data[:signature], technical: [1]) + "\n\n#{data[:webhook]}\n\n```ruby\n#{data[:callback_usage]}\n```" if data[:has_webhook]),
        "## Overrides\n\n" + data[:notes].map { |text| "- #{escape(text)}" }.join("\n"),
        "## Пример\n\n```ruby\n#{data[:usage]}\n```",
        ("### ProviderGateway\n\nexternal_method → request_method\n\n" +
          data[:logical_methods].map { |name, target| "#{md_code(name)} → #{md_code(target)}" }.join('; ') + "\n\n" +
          data[:gateway_note] unless data[:logical_methods].empty?),
        '[Code.ak](https://codeak.ru)'
      ]
      sections.compact.join("\n\n").gsub(/\n{3,}/, "\n\n") + "\n"
    end

    private

    # тут готовим короткую памятку без полного списка diagnostics и provenance
    def report_data
      operations = @ir.fetch('operations', [])
      targets = @ir.fetch('request_methods', {})
      methods = targets.filter_map do |name, target|
        matches = operations.select { |op| target.is_a?(Hash) ? op['id'] == target['operationId'] : op['role'] == target }
        [name, matches.first['role']] if matches.length == 1
      end.to_h
      payments = operations.select { |op| op['role'] == 'create' }.map do |create|
        fields = create.fetch('fields', []).filter_map do |field|
          mapping = create.fetch('field_mappings', {})[field['path']]
          next unless mapping || field['required']
          [field['path'], mapping || 'уточнить', field['required'] ? 'да' : 'нет']
        end
        {endpoint: "#{create['method'].to_s.upcase} #{create['path']}", fields: fields, minima: minimum_lines(create)}
      end
      auth = auth_rows
      webhook = operations.any? { |op| op['role'] == 'webhook' }
      count = operations.length
      noun = (11..14).cover?(count % 100) ? 'методов' : {1 => 'метод', 2 => 'метода', 3 => 'метода', 4 => 'метода'}.fetch(count % 10, 'методов')
      {
        title: @ir['title'], version: @ir['openapi'],
        summary: "#{count} #{noun} · #{auth.empty? ? 'без авторизации' : auth.map { |row| row.first.sub(/ \((?:header|query|cookie)\)\z/, '') }.join(', ')}#{webhook ? ' · webhook' : ''}",
        servers: server_rows(operations), env: env_name,
        auth: auth, connection: "ENV: #{md_code(env_name)}",
        methods: operations.map { |op| [operation_label(op), "#{op['method'].to_s.upcase} #{op['path']}"] },
        payments: payments, amount: amount_text,
        requisites: 'recipient.* берём из operation.payout_requisite: sbp.phone/bank_code/bank_name; card_number или card.number/card.card_number. Общий phone можно передать рядом с card. Тип определяем по одной ветке или явному type; конфликтующие реквизиты отклоняем.',
        conditions: @ir.fetch('required_if', []).map { |rule|
          value = rule.dig('when', 'value')
          if rule.dig('when', 'field') == 'recipient.type'
            "#{value} → #{rule['field'].delete_prefix('recipient.')}"
          else
            "#{rule.dig('when', 'field')}=#{value} → #{rule['field']}"
          end
        },
        idempotency: idempotency_text(operations), statuses: status_rows(operations),
        errors: error_rows(operations), signature: signature_rows(webhook),
        failure_codes: 'В таблице — смысл ошибки API. Result.code использует коды платформы: 401 → unauthorized, 422 → unprocessable_entity, 429 → too_many_requests. Сбой сети → service_unavailable, неверный ответ → bad_gateway, ошибка конфигурации → internal_server_error.',
        has_webhook: webhook,
        webhook: 'В HTTP-обработчике сначала проверяем подпись, затем разбираем JSON и передаём Hash в process_callback. raw_body нельзя собирать из JSON повторно. Повторы callback отслеживает приложение.',
        callback_usage: callback_usage_text,
        notes: clarification_lines, usage: usage_text(methods),
        gateway_note: 'Gateway выбирает приложение; его значение нельзя определить из OpenAPI.',
        logical_methods: methods.map { |name, role| [name, targets[name].is_a?(Hash) ? targets[name]['operationId'] : role] },
        files: ["#{@ir['provider']}_service.rb", 'INTEGRATION.md', 'fixtures.json', 'analysis.json', 'warnings.json', 'manifest.json']
      }
    end

    # отдельный адрес метода важнее общего поэтому тоже показываем его в подключении
    def server_rows(operations)
      rows = @ir.fetch('servers', []).map { |server| [server['description'] || 'Базовый адрес', server['url']] }
      common = rows.map(&:last)
      rows + operations.flat_map do |operation|
        operation.fetch('servers', []).filter_map do |server|
          [operation['role'], server['url']] unless common.include?(server['url'])
        end
      end.uniq
    end

    # имена credentials показываем как код а не как заранее экранированный html
    def auth_rows
      @ir.fetch('auth_schemes', {}).map do |name, scheme|
        kind = scheme['scheme'].to_s.downcase
        label = scheme['type'] == 'apiKey' ? "#{scheme['name']} (#{scheme['in']})" : {'bearer' => 'Bearer', 'basic' => 'Basic'}.fetch(kind, name)
        credential = scheme['credential'] || (kind == 'bearer' ? 'token' : 'api_key')
        value = kind == 'basic' ? 'credentials["username"], credentials["password"]' : "credentials[#{credential.inspect}]"
        [label, value]
      end
    end

    def amount_text
      amount = @ir.fetch('amount', {})
      return 'Пересчёт суммы нужно уточнить через overrides' unless amount['factor'] && %w[minor major].include?(amount['unit'])
      factor = amount['factor'] == 1 ? '' : " × #{amount['factor']}"
      "operation.amount#{factor} → #{{'minor' => 'минимальные единицы', 'major' => 'основные единицы'}[amount['unit']]}"
    end

    # минимум из схемы переводим обратно в единицы operation.amount
    def minimum_lines(operation)
      return [] unless operation && @ir.dig('amount', 'factor').to_f.positive?
      fields = operation.fetch('fields', [])
      currency = fields.find { |field| operation.dig('field_mappings', field['path']) == 'currency' }
      currencies = currency&.dig('schema', 'enum') || []
      fields.filter_map do |field|
        next unless operation.dig('field_mappings', field['path']) == 'amount' && field.dig('schema', 'minimum')
        number = (BigDecimal(field.dig('schema', 'minimum').to_s) / BigDecimal(@ir.dig('amount', 'factor').to_s)).to_s('F').sub(/\.0\z/, '')
        "минимум: #{number} #{currencies.empty? ? 'основные единицы' : currencies.join('/')}"
      end
    end

    def idempotency_text(operations)
      lines = operations.filter_map do |op|
        key = op['idempotency']
        next unless key && key['name']
        parameter = op.fetch('parameters', []).find { |item| item['name'] == key['name'] && item['in'] == key['in'] }
        source = parameter&.dig('schema', 'format') == 'uuid' ? 'UUIDv5(operation.id)' : 'operation.id'
        "#{key['name']}#{key['in'] == 'query' ? ' (query)' : ''} ← #{source}"
      end.uniq
      lines.empty? ? 'idempotency → не указано' : lines.join('; ')
    end

    # одинаковый http-код может означать разные ошибки у разных методов
    def error_rows(operations)
      rows = operations.flat_map { |op| op.fetch('error_mappings', {}).map { |status, error| [operation_label(op), status, error] } }
      rows.empty? ? @ir.fetch('error_mappings', {}).map { |status, error| ['все', status, error] } : rows.uniq
    end

    def signature_rows(webhook)
      return [] unless webhook
      signature = @ir.fetch('signature', {})
      return [['Подпись', 'none']] if signature['algorithm'] == 'none'
      [['Заголовок', signature['header'] || 'уточнить через overrides'], ['Алгоритм', signature['algorithm'] || 'уточнить через overrides'],
       ['Подписываемые данные', signature['signed_data'] || 'уточнить через overrides'], ['Кодировка', signature['encoding'] || 'уточнить через overrides'],
       ['Секрет', 'credentials["callback_secret"]']]
    end

    def clarification_lines
      subjects = @ir.fetch('provenance', []).select { |item| item['source'] == 'override' }.map { |item| item['subject'].to_s }.uniq
      lines = subjects.group_by { |subject| subject.split('.').first }.map do |key, entries|
        value = case key
                when 'amount' then "#{{'minor' => 'минимальные единицы', 'major' => 'основные единицы'}.fetch(@ir.dig('amount', 'unit'), 'единицы не определены')} ×#{@ir.dig('amount', 'factor')}"
                when 'required_if' then "правила (#{@ir.fetch('required_if', []).length})"
                when 'signature' then @ir.fetch('signature', {}).values_at('algorithm', 'signed_data', 'encoding').compact.join(' · ')
                else
                  count = entries.count { |subject| subject != key }
                  count.positive? ? "сопоставления (#{count})" : 'настроено'
                end
        "#{key}: #{value}"
      end
      lines.empty? ? ['нет'] : lines
    end

    def operation_label(operation)
      names = @ir.fetch('request_methods', {}).select { |_, target| target.is_a?(Hash) && target['operationId'] == operation['id'] }.keys
      names.empty? ? operation['role'] : names.join(' / ')
    end

    def status_rows(operations)
      mappings = @ir.fetch('status_mappings', {})
      values = operations.flat_map do |op|
        response = op.fetch('response_fields', []).select { |field| field['path'] == op.dig('response_mappings', 'status') }
        request = op['role'] == 'webhook' ? op.fetch('fields', []).select { |field| op.dig('field_mappings', field['path']) == 'status' } : []
        (response + request).flat_map { |field| field.dig('schema', 'enum') || [] }
      end
      mappings.to_a + values.map(&:to_s).uniq.reject { |value| mappings.key?(value) }.map { |value| [value, 'уточнить через overrides'] }
    end

    def usage_text(methods)
      name = @ir['provider'].to_s.split('_').map(&:capitalize).join
      logical = methods.find { |_, role| role == 'create' }&.first || 'create'
      code = "service = Provider::#{name}Service.new(\n  client: http_client, credentials: provider_credentials,\n  base_url: ENV.fetch('#{env_name}')\n)"
      if methods.value?('create')
        code += "\nresult = service.create_request(operation, #{logical.inspect})\nunless result.failed?\n  provider_id = result.data.dig(:result, :id)\n  # хост сам сохраняет provider_id в operation.provider_operation_key\nend"
      end
      code += "\n# после сохранения provider_operation_key\nstatus = service.fetch_status(operation)" if methods.value?('status')
      code
    end

    def callback_usage_text
      <<~RUBY.chomp
        verify = service.verify_callback_signature(raw_body, headers)
        return verify if verify.failed?

        begin
          json = raw_body.dup.force_encoding(Encoding::UTF_8)
          raise JSON::ParserError unless json.valid_encoding?
          payload = JSON.parse(json, decimal_class: BigDecimal,
            allow_duplicate_key: false, max_nesting: 100)
          service.process_callback(payload)
        rescue JSON::ParserError
          failure(:unprocessable_entity, 'Invalid callback JSON')
        end
      RUBY
    end

    # в markdown-таблице отдельно защищаем разделитель и переносы строк
    def md_table(headers, rows, technical: [])
      body = rows.map { |row| row.each_with_index.map { |cell, i| technical.include?(i) ? md_code(cell) : escape(cell) } }
      ([headers, Array.new(headers.length, '---')] + body).map { |row| '| ' + row.map { |cell| cell.to_s.gsub('|', '\\|').gsub("\n", '<br>') }.join(' | ') + ' |' }.join("\n")
    end

    # если само имя содержит обратные кавычки берём более длинный разделитель
    def md_code(value)
      text = value.to_s.gsub("\n", ' ')
      length = text.scan(/`+/).map(&:length).max.to_i
      fence = '`' * (length + 1)
      length.zero? ? "`#{text}`" : "#{fence} #{text} #{fence}"
    end

    def env_name
      "#{@ir['provider'].to_s.upcase}_BASE_URL"
    end

    def escape(value)
      CGI.escapeHTML(value.to_s)
    end
  end
end
