# frozen_string_literal: true

Gitlab::Seeder.quiet do
  GitlabSubscriptions::AddOn.names.each_key do |name|
    GitlabSubscriptions::AddOn.find_or_create_by_name(name)

    print '.'
  end
end
