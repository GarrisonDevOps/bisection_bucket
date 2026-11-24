# frozen_string_literal: true

class SmartcardController < ApplicationController
  CERT_SEPARATOR = '--'
  LOGIN_CUTOFF_LIMIT = 3.minutes

  skip_before_action :authenticate_user!
  skip_before_action :verify_authenticity_token

  before_action :check_feature_availability
  before_action :check_certificate_required_host_and_port, only: :extract_certificate
  before_action :check_certificate_headers, only: :extract_certificate
  before_action :check_certificate_param, only: :verify_certificate

  feature_category :system_access

  def auth
    redirect_to extract_certificate_smartcard_url(extract_certificate_url_options)
  end

  def extract_certificate
    redirect_to verify_certificate_smartcard_url(verify_certificate_url_options)
  end

  def verify_certificate
    sign_in_with(client_certificate)
  end

  private

  def extract_certificate_url_options
    {
      host: ::Gitlab.config.smartcard.client_certificate_required_host,
      port: ::Gitlab.config.smartcard.client_certificate_required_port,
      provider: permitted_params[:provider]
    }.compact
  end

  def verify_certificate_url_options
    nonce = Gitlab::Utils.ensure_utf8_size(SecureRandom.urlsafe_base64(12), bytes: 12.bytes)
    timestamped_cert = "#{certificate_from_header}#{CERT_SEPARATOR}#{Time.now.utc.to_i}"
    encrypted_cert = Gitlab::CryptoHelper.aes256_gcm_encrypt(timestamped_cert, nonce: nonce)

    {
      host: ::Gitlab.config.gitlab.host,
      port: ::Gitlab.config.gitlab.port,
      provider: permitted_params[:provider],
      client_certificate: CGI.escape(encrypted_cert),
      nonce: nonce
    }.compact
  end

  def client_certificate
    if ldap_provider?
      Gitlab::Auth::Smartcard::LdapCertificate.new(
        permitted_params[:provider],
        certificate_from_encrypted_param,
        Current.organization
      )
    else
      Gitlab::Auth::Smartcard::Certificate.new(
        certificate_from_encrypted_param,
        Current.organization
      )
    end
  end

  def ldap_provider?
    permitted_params[:provider].present?
  end

  def permitted_params
    params.permit(:provider, :client_certificate, :nonce)
  end

  def sign_in_with(certificate)
    user = certificate.find_or_create_user
    unless user&.persisted?
      flash[:alert] = _('Failed to sign in using smart card authentication.')
      redirect_to new_user_session_path

      return
    end

    store_active_session
    log_audit_event(user, with: certificate.auth_method, ip_address: request.remote_ip)
    sign_in_and_redirect(user)
  end

  def certificate_from_header
    @certificate_from_header ||= nginx_certificate_header || envoy_xfcc_cert
  end

  def nginx_certificate_header
    request.headers['HTTP_X_SSL_CLIENT_CERTIFICATE'].presence
  end

  def envoy_xfcc_cert
    request.headers['HTTP_X_FORWARDED_CLIENT_CERT']
      .to_s
      .split(';')
      .find { |e| e.start_with?('Cert=') }
      .to_s
      .delete_prefix('Cert=')
      .split(',')
      .last
      .to_s
      .delete_prefix('"')
      .delete_suffix('"')
      .presence
  end

  def decrypted_certificate_param
    @decrypted_certificate_param ||= begin
      param = permitted_params[:client_certificate]
      nonce = permitted_params[:nonce]

      if param && nonce
        unescaped_param = CGI.unescape(param)
        Gitlab::CryptoHelper.aes256_gcm_decrypt(unescaped_param, nonce: nonce)
      end
    end
  end

  def certificate_from_encrypted_param
    decrypted_param = decrypted_certificate_param
    return unless decrypted_param

    certificate_param = decrypted_param.rpartition(CERT_SEPARATOR).first
    certificate_string = CGI.unescape(certificate_param)
    if certificate_string.include?("\n")
      # NGINX forwarding the $ssl_client_escaped_cert variable
      certificate_string
    else
      # older version of NGINX forwarding the now deprecated $ssl_client_cert variable
      certificate_param.gsub(/ (?!CERTIFICATE)/, "\n")
    end
  end

  def timestamp_from_encrypted_param
    decrypted_param = decrypted_certificate_param
    return unless decrypted_param

    timestamp_param = decrypted_param.rpartition(CERT_SEPARATOR).last
    Time.at(timestamp_param.to_i).utc
  end

  def check_feature_availability
    render_404 unless ::Gitlab::Auth::Smartcard.enabled?
  end

  def check_certificate_required_host_and_port
    unless request.host == ::Gitlab.config.smartcard.client_certificate_required_host &&
        request.port == ::Gitlab.config.smartcard.client_certificate_required_port
      render_404
    end
  end

  def check_certificate_headers
    unless certificate_from_header.present?
      access_denied!(_('Smartcard authentication failed: client certificate header is missing.'), 401)
    end
  end

  def check_certificate_param
    unless decrypted_certificate_param.present?
      access_denied!(_('Smartcard authentication failed: client certificate header is missing.'), 401)
      return
    end

    if login_expired? || login_started_in_future?
      access_denied!(_('Smartcard authentication failed: login process exceeded the time limit.'), 401)
    end
  end

  def login_expired?
    (Time.now.utc - timestamp_from_encrypted_param) > LOGIN_CUTOFF_LIMIT
  end

  def login_started_in_future?
    timestamp_from_encrypted_param > Time.now.utc
  end

  def store_active_session
    Gitlab::Auth::Smartcard::SessionEnforcer.new.update_session
  end

  def log_audit_event(user, options = {})
    ::Gitlab::Audit::Auditor.audit({
      name: "smartcard_authentication_created",
      author: user,
      scope: user,
      target: user,
      message: "User authenticated with smartcard",
      additional_details: options
    })
  end

  def after_sign_in_path_for(resource)
    stored_location_for(:redirect) || stored_location_for(resource) || root_url(port: Gitlab.config.gitlab.port)
  end
end
