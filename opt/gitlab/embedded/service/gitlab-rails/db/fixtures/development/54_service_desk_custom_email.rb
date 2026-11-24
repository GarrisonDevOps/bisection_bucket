# frozen_string_literal: true

# Seeds the Service Desk custom email credential table, which is empty in the upgrade stop dump,
# so migrations touching it were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::ServiceDeskCustomEmail # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  # An address rather than a hostname, because the credential validates it through UrlBlocker and
  # the dump is generated without a network to resolve a name against.
  SMTP_ADDRESS = '10.0.0.1'
  SMTP_PORT = 587

  attr_reader :project

  def initialize
    @project = Project.order(:id).first
  end

  # The SMTP username and password are encrypted per attribute, so a row written straight to the
  # table would hold plaintext where the application stores ciphertext.
  def seed!
    return warn "\nSkipping service desk credential seed: no project available" if project.nil?
    return if ::ServiceDesk::CustomEmailCredential.exists?(project_id: project.id)

    ::ServiceDesk::CustomEmailCredential.create!(
      project: project, smtp_address: SMTP_ADDRESS, smtp_port: SMTP_PORT,
      smtp_username: 'seeded-smtp-user', smtp_password: 'seeded-smtp-password',
      smtp_authentication: :plain)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating service desk custom email data"

  Gitlab::Seeder::ServiceDeskCustomEmail.new.seed!
end
