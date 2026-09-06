# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'
require 'json'
require 'digest'
require 'open3'
require 'rbconfig'

module Integrator
  class Generator
    def initialize(ir)
      @ir = ir
    end

    # сначала собираем файлы во временной папке и проверяем ruby перед переносом
    def generate(output)
      target = safe_output(output)
      provider = @ir.fetch('provider')
      raise Error, 'Unsafe provider filename' unless provider.match?(/\A[a-z][a-z0-9_]*\z/)
      report = ReportGenerator.new(@ir)
      artifacts = {
        "#{provider}_service.rb" => ServiceGenerator.new(@ir).render,
        'INTEGRATION.md' => report.integration,
        'fixtures.json' => json(FixtureGenerator.new(@ir).generate),
        'analysis.json' => json(@ir),
        'warnings.json' => json(@ir.fetch('diagnostics', [])),
        'generation_report.html' => report.html
      }
      artifacts['manifest.json'] = json({'format' => 1, 'provider' => provider, 'files' => artifacts.transform_values { |content| Digest::SHA256.hexdigest(content) }})
      check_existing(target, artifacts)
      FileUtils.mkdir_p(File.dirname(target))
      Dir.mktmpdir('.integration-', File.dirname(target)) do |staging|
        artifacts.each { |name, content| File.write(File.join(staging, name), content, mode: 'wb') }
        ruby_file = File.join(staging, "#{provider}_service.rb")
        stdout, stderr, status = Open3.capture3(RbConfig.ruby, '-c', ruby_file)
        raise Error, "Generated Ruby is invalid: #{stdout} #{stderr}" unless status.success?
        JSON.parse(File.read(File.join(staging, 'fixtures.json')))
        FileUtils.mkdir_p(target)
        artifacts.each_key { |name| FileUtils.mv(File.join(staging, name), File.join(target, name)) }
      end
      artifacts.keys.map { |name| File.join(target, name) }
    rescue SystemCallError, JSON::ParserError => e
      raise Error, "Cannot generate artifacts: #{e.message}"
    end

    private

    def json(value)
      JSON.pretty_generate(value) + "\n"
    end

    # не разрешаем писать через родительские пути и символические ссылки
    def safe_output(output)
      raise Error, 'Output cannot contain parent traversal (..)' if output.to_s.split(/[\\\/]/).include?('..')
      target = File.expand_path(output)
      raise Error, 'Output must be a dedicated directory' if target == File.dirname(target) || target == Dir.pwd
      current = target
      loop do
        raise Error, "Output path contains a symbolic link: #{current}" if File.symlink?(current)
        parent = File.dirname(current)
        break if parent == current
        current = parent
      end
      target
    end

    # перезаписываем только свои неизменённые файлы сверяя их с manifest
    def check_existing(target, artifacts)
      return unless File.exist?(target)
      raise Error, 'Output must be a directory' unless File.directory?(target)
      manifest_path = File.join(target, 'manifest.json')
      raise Error, 'Refusing to overwrite a symlink manifest' if File.symlink?(manifest_path)
      manifest = File.file?(manifest_path) ? JSON.parse(File.read(manifest_path)) : {}
      unless manifest.is_a?(Hash) && (!manifest.key?('files') || manifest['files'].is_a?(Hash))
        raise Error, 'Invalid output manifest; choose a new output directory'
      end
      artifacts.each_key do |name|
        path = File.join(target, name)
        raise Error, "Refusing to overwrite symlink #{path}" if File.symlink?(path)
        next unless File.exist?(path)
        next if name == 'manifest.json' && manifest['format'] == 1 && manifest['provider'] == @ir['provider']
        digest = manifest.fetch('files', {})[name]
        unless File.file?(path) && digest && Digest::SHA256.file(path).hexdigest == digest
          raise Error, "Refusing to overwrite unknown or modified file #{path}; choose a new output directory"
        end
      end
    end
  end
end
