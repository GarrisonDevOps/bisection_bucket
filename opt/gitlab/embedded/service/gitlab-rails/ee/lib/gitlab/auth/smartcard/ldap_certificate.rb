# frozen_string_literal: true

module Gitlab
  module Auth
    module Smartcard
      class LdapCertificate < Gitlab::Auth::Smartcard::Base
        include Gitlab::Utils::StrongMemoize

        def initialize(provider, certificate, organization)
          super(certificate, organization)

          @provider = provider
        end

        def auth_method
          'smartcard_ldap'
        end

        def find_or_create_user
          # if passed certificate is invalid, @certificate may be nil
          return unless @certificate.present? && ldap_user.present?

          super
        end

        private

        def find_user
          identity = ::Identity.find_by_extern_uid(@provider, ldap_user.dn)
          identity&.user
        end

        def create_identity_for_existing_user
          user = User.find_by_email(ldap_user.email.first)

          return if user.nil? || user.ldap_user?

          create_ldap_certificate_identity_for(user)
          user
        end

        def create_user
          user_params = {
            name: ldap_user.name,
            username: username,
            email: ldap_user.email.first,
            extern_uid: ldap_user.dn,
            provider: @provider,
            password: password,
            password_confirmation: password,
            password_automatically_set: true,
            skip_confirmation: true,
            organization_id: organization.id
          }

          Users::AuthorizedCreateService.new(nil, user_params).execute
        end

        def create_ldap_certificate_identity_for(user)
          user.identities.create(provider: @provider, extern_uid: ldap_user.dn)
        end

        def adapter
          @adapter ||= Gitlab::Auth::Ldap::Adapter.new(@provider)
        end

        def ldap_user
          if use_ad_certificate_matching?
            ::Gitlab::Auth::Ldap::Person.find_by_ad_certificate_field(alt_security_id, adapter)
          else
            ::Gitlab::Auth::Ldap::Person.find_by_certificate_issuer_and_serial(issuer_dn, serial, adapter)
          end
        end
        strong_memoize_attr :ldap_user

        def issuer_dn
          @certificate.issuer.to_s(OpenSSL::X509::Name::RFC2253)
        end
        strong_memoize_attr :issuer_dn

        def reverse_issuer_dn
          reverse_issuer = @certificate.issuer.to_a.reverse
          OpenSSL::X509::Name.new(reverse_issuer).to_s(OpenSSL::X509::Name::RFC2253)
        end
        strong_memoize_attr :reverse_issuer_dn

        def serial
          @serial ||= @certificate.serial.to_s
        end

        # in ActiveDirectory, serial numbers are typically stored in
        # reverse-byte-order hex from the human-readable version
        # https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-certificate-based-authentication#issuer-and-serial-number-manual-mapping
        def reverse_serial
          @reverse_serial ||= @certificate.serial.to_s(16)   #=> "deadbeef"
                                                 .scan(/../) #=> ["de", "ad", "be", "ef"]
                                                 .reverse    #=> ["ef", "be", "ad", "de"]
                                                 .join       #=> "efbeadde"
                                                 .downcase
        end

        def subject
          @subject ||= @certificate.subject.to_s
        end

        def subject_dn
          @certificate.subject.to_s(OpenSSL::X509::Name::RFC2253)
        end
        strong_memoize_attr :subject_dn

        def reverse_subject_dn
          reverse_subject = @certificate.subject.to_a.reverse
          OpenSSL::X509::Name.new(reverse_subject).to_s(OpenSSL::X509::Name::RFC2253)
        end
        strong_memoize_attr :reverse_subject_dn

        # adapter.config.active_directory defaults to true even for non-AD providers
        # for legacy reasons. We check for opt-in for AD-specific cert behavior using the
        # smartcard_ad_cert_format config field
        def use_ad_certificate_matching?
          !!adapter.config.active_directory && smartcard_ad_cert_format.present?
        end

        def smartcard_ad_cert_format
          adapter.config.smartcard_ad_cert_format
        end

        # formats gathered from:
        # https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication-certificateuserids#supported-patterns-for-certificate-user-ids
        #
        # issuer_fbo formats added because some AD servers match issuer DN using forward-byte-order rather than
        # the typical byte order cited in the Microsoft docs
        def alt_security_id
          case smartcard_ad_cert_format
          when 'principal_name'
            "X509:<PN>#{subject}"
          when 'rfc822_name'
            "X509:<RFC822>#{subject}"
          when 'issuer_and_subject'
            issuer_and_subject
          when 'reverse_issuer_and_subject'
            reverse_issuer_and_subject
          when 'reverse_issuer_and_reverse_subject'
            "X509:<I>#{reverse_issuer_dn}<S>#{reverse_subject_dn}"
          when 'subject'
            subject_alt_security_id
          when 'issuer_and_serial_number'
            "X509:<I>#{issuer_dn}<SR>#{reverse_serial}"
          when 'reverse_issuer_and_serial_number'
            "X509:<I>#{reverse_issuer_dn}<SR>#{reverse_serial}"
          else
            raise _('Missing or invalid configuration field: :smartcard_ad_cert_format')
          end
        end

        def issuer_and_subject
          "X509:<I>#{issuer_dn}<S>#{subject_dn}"
        end

        def reverse_issuer_and_subject
          "X509:<I>#{reverse_issuer_dn}<S>#{subject_dn}"
        end

        def subject_alt_security_id
          "X509:<S>#{subject_dn}"
        end

        def username
          return unless ldap_user.present?

          ::Namespace.clean_path(ldap_user.username)
        end
      end
    end
  end
end
