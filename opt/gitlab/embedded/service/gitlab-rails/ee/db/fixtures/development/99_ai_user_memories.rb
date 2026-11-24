# frozen_string_literal: true

Gitlab::Seeder.quiet do
  user = User.first
  next unless user

  # Namespace-scoped memory (GitLab.com pattern)
  namespace = Group.top_level.first
  if namespace
    Ai::NamespaceUserMemory.find_or_create_by!(user: user, namespace: namespace) do |memory|
      memory.content = 'I prefer concise responses and Ruby examples.'
    end
    print '.'
  end

  # Organization-scoped memory (self-managed pattern)
  org = user.organization
  if org
    Ai::OrganizationUserMemory.find_or_create_by!(user: user, organization: org) do |memory|
      memory.content = 'I prefer concise responses and Ruby examples.'
    end
    print '.'
  end
end
