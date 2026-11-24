# frozen_string_literal: true

module ClickHouse
  module Client
    class Configuration
      # Configuration options:
      #
      # *register_database* (method): registers a database, the following arguments are required:
      #   - database: database name
      #   - url: URL and port to the HTTP interface
      #   - username
      #   - password
      #   - variables (optional): configuration for the client
      #
      # *http_post_proc*: A callable object for invoking the HTTP request.
      #   The object must handle the following parameters: url, headers, body
      #   and return a ClickHouse::Client::Response object.
      #
      # *json_parser*: object for parsing JSON strings, it should respond to the "parse" method
      #
      # *logger*: object for receiving logger commands. Default `$stdout`
      # *log_proc*: any output (e.g. structure) to wrap around the query for every statement
      #
      # *register_typecaster* (method): registers a custom typecaster for a column type,
      #   taking precedence over the built-in typecasters. Arguments:
      #   - type: column type as a String (exact match) or a Regexp
      #   - typecaster: a callable object receiving the column metadata Hash
      #     (e.g. { 'name' => 'title', 'type' => 'String' }) and the raw value
      #
      # Example:
      #
      # ClickHouse::Client.configure do |c|
      #   c.register_database(:main,
      #     database: 'gitlab_clickhouse_test',
      #     url: 'http://localhost:8123',
      #     username: 'default',
      #     password: 'clickhouse',
      #     variables: {
      #       join_use_nulls: 1 # treat JOINs as per SQL standard
      #     }
      #   )
      #
      #   c.logger = MyLogger.new
      #   c.log_proc = ->(query) do
      #     { query_body: query.to_redacted_sql }
      #   end
      #
      #   c.http_post_proc = lambda do |url, headers, body|
      #     options = {
      #       headers: headers,
      #       body: body,
      #       allow_local_requests: false
      #     }
      #
      #     response = Gitlab::HTTP.post(url, options)
      #     ClickHouse::Client::Response.new(response.body, response.code)
      #   end
      #
      #   c.json_parser = JSON
      #
      #   c.register_typecaster('String', ->(meta, value) do
      #     meta['name'].match?(/\w+_json\z/) ? JSON.parse(value) : value
      #   end)
      # end
      attr_accessor :http_post_proc, :json_parser, :logger, :log_proc
      attr_reader :databases, :typecasters

      def initialize
        @databases = {}
        @typecasters = {}
        @http_post_proc = nil
        @json_parser = JSON
        @logger = ::Logger.new($stdout)
        @log_proc = ->(query) { query.to_sql }
      end

      def register_database(name, **args)
        raise ConfigurationError, "The database '#{name}' is already registered" if @databases.key?(name)

        @databases[name] = Database.new(**args)
      end

      def register_typecaster(type, typecaster)
        raise ConfigurationError, "The typecaster for '#{type}' is already registered" if @typecasters.key?(type)

        @typecasters[type] = typecaster
      end

      def validate!
        raise ConfigurationError, "The 'http_post_proc' option is not configured" unless @http_post_proc
        raise ConfigurationError, "The 'json_parser' option is not configured" unless @json_parser
      end
    end
  end
end
