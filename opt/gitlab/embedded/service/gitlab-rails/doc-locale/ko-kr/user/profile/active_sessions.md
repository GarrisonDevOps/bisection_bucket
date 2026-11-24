---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 활성 세션
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 계정에 로그인한 모든 디바이스를 나열합니다. 세션을 검토하고 인식하지 못한 세션을 해지할 수 있습니다.

## 모든 활성 세션 나열 {#list-all-active-sessions}

모든 활성 세션을 나열하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **활성 세션**을 선택하세요.

![활성 세션 목록](img/active_sessions_list_v12_7.png)

## 활성 세션 제한 {#active-sessions-limit}

GitLab은 사용자가 한 번에 최대 100개의 활성 세션을 가질 수 있도록 허용합니다. 활성 세션 수가 100을 초과하면 가장 오래된 세션이 삭제됩니다.

## 세션 해지 {#revoke-a-session}

활성 세션을 해지하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **활성 세션**을 선택하세요.
1. 세션 옆의 **해지**를 선택하세요. 현재 세션은 GitLab에서 로그아웃되므로 해지할 수 없습니다.

> [!note]
> 세션이 해지되면 모든 장치의 모든 **계정 정보 저장** 토큰이 해지됩니다. **계정 정보 저장**에 대한 자세한 내용은 [로그인에 사용되는 쿠키](_index.md#cookies-used-for-sign-in)를 참조하세요.

## Rails 콘솔을 통해 세션 해지 {#revoke-sessions-through-the-rails-console}

Rails 콘솔을 통해 사용자 세션을 해지할 수도 있습니다. 이를 사용하여 여러 세션을 동시에 해지할 수 있습니다.

### 모든 사용자의 모든 세션 해지 {#revoke-all-sessions-for-all-users}

모든 사용자의 모든 세션을 해지하려면:

1. [Rails 콘솔 세션 시작](../../administration/operations/rails_console.md#starting-a-rails-console-session)합니다.
1. 선택 사항. 다음 명령으로 모든 활성 세션을 나열합니다:

   ```ruby
   # Show all users with active sessions
    puts "=== Currently Logged In Users ==="
    User.find_each do |user|
        sessions = ActiveSession.list(user)
        if sessions.any?
            puts "\n#{user.username} (#{user.name}):"
            sessions.each do |session|
                puts "  - IP: #{session.ip_address}, Browser: #{session.browser}, Last active: #{session.updated_at}"
            end
        end
    end
   ```

1. 다음 명령으로 모든 세션을 해지합니다:

   ```ruby
   User.find_each do |user|
      ActiveSession.destroy_all_but_current(user, nil)
   end
   ```

1. 선택 사항. "모든 활성 세션 나열" 명령을 다시 실행하여 모든 세션이 해지되었는지 확인합니다.

### 그룹의 모든 사용자에 대한 모든 세션 해지 {#revoke-all-sessions-for-all-users-of-a-group}

1. 다음 스크립트를 GitLab 인스턴스에 저장하세요. 예를 들어, `scripts/session_revocation/revoke_group_sessions.rb`입니다.

   ```ruby
   # frozen_string_literal: true
   #
   # Revoke all active sessions for members of a group, including:
   # - Direct and inherited members of the top-level group
   # - Direct members of all subgroups
   # - Members invited via group shares at the top-level and subgroup level
   #
   # Usage (Rails console):
   #   DRY_RUN = true
   #   GROUP_IDENTIFIER = 'your-group-path' # or numeric ID
   #   load 'scripts/session_revocation/revoke_group_sessions.rb'

   DRY_RUN = true unless defined?(DRY_RUN)
   # Replace `your-group-path` with your group ID or the full path to your group
   GROUP_IDENTIFIER = 'your-group-path' unless defined?(GROUP_IDENTIFIER)

   # ---------------------------------------------------------------

   def find_group(identifier)
      # Try finding by full path first (handles numeric group names)
      group = Group.find_by_full_path(identifier.to_s)
      return group if group

      # Fallback to ID lookup if path not found and identifier is numeric
      if identifier.is_a?(Integer) || identifier.to_s.match?(/\A\d+\z/)
         Group.find_by(id: identifier)
      end
   end

   def collect_member_user_ids(group)
      user_ids = Set.new

      # Direct and inherited members of the top-level group
      user_ids.merge(group.members_with_parents.pluck(:user_id))

      # Members invited via group shares into the top-level group
      group.shared_with_group_links.each do |link|
         user_ids.merge(link.shared_with_group.members_with_parents.pluck(:user_id))
      end

      # Traverse all subgroups
      group.descendants.find_each do |subgroup|
         # Direct members of each subgroup
         user_ids.merge(subgroup.members.pluck(:user_id))

         # Members invited via group shares into each subgroup
         subgroup.shared_with_group_links.each do |link|
            user_ids.merge(link.shared_with_group.members_with_parents.pluck(:user_id))
         end
      end

      user_ids.to_a
   end

   def revoke_sessions_for_group(group, dry_run:)
      member_user_ids = collect_member_user_ids(group)

      puts "Found #{member_user_ids.count} unique members in group '#{group.full_path}' (including subgroups and group shares)"

      # Only process active, non-bot human users to avoid unnecessary Redis lookups
      users = User.active.human.id_in(member_user_ids)

      revoked_sessions = 0
      affected_users = []
      skipped_users = []

      users.find_each do |user|
         sessions = ActiveSession.list(user)

         if sessions.empty?
            skipped_users << user.username
            next
         end

         session_ids = sessions.map(&:session_private_id).compact

         if session_ids.empty?
            puts "  [WARN] User #{user.username} has sessions but all session_private_ids are nil, skipping."
            skipped_users << user.username
            next
         end

         unless dry_run
            Gitlab::Redis::Sessions.with do |redis|
               ActiveSession.destroy_sessions(redis, user, session_ids)
            end

            # Emit audit event for security traceability
            Gitlab::AppLogger.info(
               message: "Sessions revoked via admin script",
               user_id: user.id,
               username: user.username,
               session_count: session_ids.size,
               group: group.full_path,
               performed_at: Time.current.iso8601
            )
         end

         revoked_sessions += session_ids.size
         affected_users << user.username
      end

      [revoked_sessions, affected_users, skipped_users]
   end

   # ---------------------------------------------------------------

   group = find_group(GROUP_IDENTIFIER)

   if group.nil?
      puts "ERROR: Group '#{GROUP_IDENTIFIER}' not found. Aborting."
   end

   puts "=== Session Revocation #{DRY_RUN ? '(DRY RUN)' : '(LIVE)'} ==="
   puts "Group: #{group.full_path} (ID: #{group.id})"
   puts

   revoked_sessions, affected_users, skipped_users = revoke_sessions_for_group(group, dry_run: DRY_RUN)

   prefix = DRY_RUN ? "[DRY RUN] Would revoke" : "Revoked"
   puts "#{prefix} #{revoked_sessions} sessions for #{affected_users.size} users"
   puts "Users affected: #{affected_users.sort.join(', ')}" if affected_users.any?
   puts "Users skipped (no active sessions): #{skipped_users.size}" if skipped_users.any?

   if DRY_RUN && revoked_sessions.positive?
      puts "\nTo actually revoke sessions, set DRY_RUN = false and run again."
   end
   ```

1. [Rails 콘솔 세션 시작](../../administration/operations/rails_console.md#starting-a-rails-console-session)합니다.
1. 다음 명령을 실행하여 그룹을 대상으로 합니다. `your-group-path`을 그룹 ID 또는 그룹의 전체 경로로 바꿉니다:

   ```ruby
   GROUP_IDENTIFIER = 'your-group-path'
   ```

1. 다음 명령을 실행하여 그룹의 모든 활성 세션을 나열합니다:

   ```ruby
   DRY_RUN = true
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

1. 다음 명령을 실행하여 그룹의 모든 세션을 해지합니다:

   ```ruby
   DRY_RUN = false
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

1. 다음 명령을 실행하여 모든 세션이 닫혔는지 확인합니다. 출력에는 0개의 활성 세션이 나열되어야 합니다:

   ```ruby
   DRY_RUN = true
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

### 특정 사용자의 모든 세션 해지 {#revoke-all-sessions-for-a-user}

특정 사용자의 모든 세션을 해지하려면:

1. [Rails 콘솔 세션 시작](../../administration/operations/rails_console.md#starting-a-rails-console-session)합니다.
1. 다음 명령으로 사용자를 찾습니다:

   - 사용자 이름으로:

     ```ruby
     user = User.find_by_username 'exampleuser'
     ```

   - 사용자 ID로:

     ```ruby
     user = User.find(123)
     ```

   - 이메일 주소로:

     ```ruby
     user = User.find_by(email: 'user@example.com')
     ```

1. 선택 사항. 다음 명령으로 사용자의 모든 활성 세션을 나열합니다:

   ```ruby
   ActiveSession.list(user)
   ```

1. 다음 명령으로 모든 세션을 해지합니다:

   ```ruby
   ActiveSession.list(user).each { |session| ActiveSession.destroy_session(user, session.session_private_id) }
   ```

1. 다음 명령으로 모든 세션이 닫혔는지 확인합니다:

   ```ruby
   # If all sessions are closed, returns an empty array.
   ActiveSession.list(user)
   ```
