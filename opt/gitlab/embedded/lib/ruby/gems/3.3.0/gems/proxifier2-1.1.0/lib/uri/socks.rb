require "uri/generic"

module URI
  class SOCKS < Generic
    DEFAULT_PORT = 1080
    COMPONENT = [:scheme, :userinfo, :host, :port, :query].freeze
  end

  class SOCKS4 < SOCKS
  end

  class SOCKS4A < SOCKS
  end

  begin
    @@schemes["SOCKS4"] = SOCKS4
    @@schemes["SOCKS"] = SOCKS
    @@schemes["SOCKS5"] = SOCKS
    @@schemes["SOCKS4A"] = SOCKS4A
  rescue
    register_scheme 'SOCKS4', SOCKS4
    register_scheme 'SOCKS', SOCKS
    register_scheme 'SOCKS5', SOCKS
    register_scheme 'SOCKS4A', SOCKS4A
  end
end
