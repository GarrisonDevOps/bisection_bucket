# frozen_string_literal: true

module RemoteDevelopment
  class NetworkPolicyEgressValidator < ActiveModel::EachValidator
    # @param [RemoteDevelopment::WorkspacesAgentConfig] record
    # @param [Symbol] attribute
    # @param [Array] value
    # @return [void]
    def validate_each(record, attribute, value)
      unless value.is_a?(Array)
        record.errors.add(attribute, _("must be an array"))
        return
      end

      value.each do |egress_rule|
        unless egress_rule.is_a?(Hash)
          record.errors.add(attribute, _("must be an array of hash"))
          break
        end

        # noinspection RubyMismatchedArgumentType,RubyArgCount - RubyMine is resolving egress_rule as array, not hash
        allow = egress_rule.deep_symbolize_keys.fetch(:allow, nil)
        # noinspection RubyMismatchedArgumentType,RubyArgCount - RubyMine is resolving egress_rule as array, not hash
        except = egress_rule.deep_symbolize_keys.fetch(:except, [])

        if allow.nil?
          record.errors.add(
            attribute,
            _("must be an array of hash containing 'allow' attribute of type string")
          )
          break
        end

        unless allow.is_a?(String)
          record.errors.add(
            attribute,
            format(_("'allow: %{allow}' must be a string"), allow: allow)
          )
          break
        end

        allow_validator = IpCidrValidator.new(attributes: attribute)
        allow_validator.validate_each(record, attribute, allow)

        unless except.is_a?(Array)
          record.errors.add(
            attribute,
            format(_("'except: %{except}' must be an array of string"), except: except)
          )
          break
        end

        except_validator = IpCidrArrayValidator.new(attributes: attribute)
        except_validator.validate_each(record, attribute, except)
      end

      nil
    end
  end
end
