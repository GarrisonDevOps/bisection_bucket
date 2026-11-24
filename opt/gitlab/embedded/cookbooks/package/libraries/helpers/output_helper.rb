require 'json'

module OutputHelper
  # Renders a value as a double-quoted string literal. A JSON string is also a
  # valid YAML double-quoted scalar, whereas String#inspect is not: it emits
  # `\#{`, `\#$`, `\#@` and `\u{...}` escapes that Psych rejects. JSON leaves
  # DEL, C1 controls and U+FFFE/U+FFFF raw, which YAML forbids, so escape them.
  def quote(string)
    string.to_s.to_json.gsub(/[\u007F-\u009F\uFFFE\uFFFF]/) { |c| format('\u%04X', c.ord) } unless string.nil?
  end

  def print_ruby_object(object)
    object.ai(plain: true)
  end
end
