# frozen_string_literal: true

class UseMemberRolesIdSeqForAdminRoles < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    with_lock_retries do
      execute("ALTER TABLE admin_roles ALTER COLUMN id SET DEFAULT nextval('member_roles_id_seq'::regclass)")
    end
  end

  def down
    with_lock_retries do
      execute("ALTER TABLE admin_roles ALTER COLUMN id SET DEFAULT nextval('admin_roles_id_seq'::regclass)")
    end
  end
end
