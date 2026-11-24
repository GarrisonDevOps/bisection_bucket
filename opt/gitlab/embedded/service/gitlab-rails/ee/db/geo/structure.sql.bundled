CREATE TABLE abuse_report_upload_registry (
    id bigint NOT NULL,
    abuse_report_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_092ecba666 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_5e7625c70b CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_bcef1e1a3b CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_dfb1ef19d9 CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE abuse_report_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE abuse_report_upload_registry_id_seq OWNED BY abuse_report_upload_registry.id;

CREATE TABLE achievement_upload_registry (
    id bigint NOT NULL,
    achievement_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_530a6db824 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_9a06e63fdd CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_9e9800aaf6 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_d96ae068de CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE achievement_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE achievement_upload_registry_id_seq OWNED BY achievement_upload_registry.id;

CREATE TABLE ai_vectorizable_file_upload_registry (
    id bigint NOT NULL,
    ai_vectorizable_file_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_03a52f6c2d CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_227d7134c6 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_40ebb5beea CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_758d624daf CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE ai_vectorizable_file_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE ai_vectorizable_file_upload_registry_id_seq OWNED BY ai_vectorizable_file_upload_registry.id;

CREATE TABLE alert_management_metric_image_upload_registry (
    id bigint NOT NULL,
    alert_management_metric_image_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_09024e4a09 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_29c9bb7315 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_dc2ed0248e CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_df60246fca CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE alert_management_metric_image_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE alert_management_metric_image_upload_registry_id_seq OWNED BY alert_management_metric_image_upload_registry.id;

CREATE TABLE appearance_upload_registry (
    id bigint NOT NULL,
    appearance_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_39d89717a6 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_91cb6ad8d9 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_c3aa1ade2a CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_d64f28216a CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE appearance_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE appearance_upload_registry_id_seq OWNED BY appearance_upload_registry.id;

CREATE TABLE ar_internal_metadata (
    key character varying NOT NULL,
    value character varying,
    created_at timestamp(6) without time zone NOT NULL,
    updated_at timestamp(6) without time zone NOT NULL
);

CREATE TABLE bulk_import_export_upload_upload_registry (
    id bigint NOT NULL,
    bulk_import_export_upload_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_1ef654449c CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_2e9978efef CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_dc2f33047d CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_f00d8a63d1 CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE bulk_import_export_upload_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE bulk_import_export_upload_upload_registry_id_seq OWNED BY bulk_import_export_upload_upload_registry.id;

CREATE TABLE ci_secure_file_registry (
    id bigint NOT NULL,
    ci_secure_file_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_17bd5fc9fa CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_420f14e38c CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_5644befead CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE ci_secure_file_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE ci_secure_file_registry_id_seq OWNED BY ci_secure_file_registry.id;

CREATE TABLE container_repository_registry (
    id integer NOT NULL,
    container_repository_id integer NOT NULL,
    state character varying,
    retry_count integer DEFAULT 0,
    last_sync_failure character varying,
    retry_at timestamp without time zone,
    last_synced_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    state_for_type_change integer,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_state smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_failure text,
    CONSTRAINT check_9b8292bb64 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE container_repository_registry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE container_repository_registry_id_seq OWNED BY container_repository_registry.id;

CREATE TABLE dependency_list_export_part_upload_registry (
    id bigint NOT NULL,
    dependency_list_export_part_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_1a3c91eb4a CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_73d2ea2bfc CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_d5981e6780 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_f69f4b181e CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE dependency_list_export_part_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dependency_list_export_part_upload_registry_id_seq OWNED BY dependency_list_export_part_upload_registry.id;

CREATE TABLE dependency_list_export_upload_registry (
    id bigint NOT NULL,
    dependency_list_export_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_1cbfcaf7af CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_6e4d7aa3fe CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_a296524fb2 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_e370ec7ea5 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE dependency_list_export_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dependency_list_export_upload_registry_id_seq OWNED BY dependency_list_export_upload_registry.id;

CREATE TABLE dependency_proxy_blob_registry (
    id bigint NOT NULL,
    dependency_proxy_blob_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_d14529e1aa CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_d3ca83a09e CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_f49c2b49ff CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE dependency_proxy_blob_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dependency_proxy_blob_registry_id_seq OWNED BY dependency_proxy_blob_registry.id;

CREATE TABLE dependency_proxy_manifest_registry (
    id bigint NOT NULL,
    dependency_proxy_manifest_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_75dff69e5a CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_925e921a2c CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_a0ddec148d CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE dependency_proxy_manifest_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE dependency_proxy_manifest_registry_id_seq OWNED BY dependency_proxy_manifest_registry.id;

CREATE TABLE design_management_action_upload_registry (
    id bigint NOT NULL,
    design_management_action_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_21db8a9734 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_98356b2bf7 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_b8c07dc54d CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_c6d5a0d260 CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE design_management_action_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE design_management_action_upload_registry_id_seq OWNED BY design_management_action_upload_registry.id;

CREATE TABLE design_management_repository_registry (
    id bigint NOT NULL,
    design_management_repository_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    missing_on_primary boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    CONSTRAINT check_0fb2f801b1 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_5fc5c30cb0 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE design_management_repository_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE design_management_repository_registry_id_seq OWNED BY design_management_repository_registry.id;

CREATE TABLE event_log_states (
    event_id bigint NOT NULL,
    created_at timestamp without time zone NOT NULL
);

CREATE SEQUENCE event_log_states_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE event_log_states_event_id_seq OWNED BY event_log_states.event_id;

CREATE TABLE file_registry (
    id integer NOT NULL,
    file_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    retry_count integer DEFAULT 0,
    retry_at timestamp without time zone,
    missing_on_primary boolean DEFAULT false NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    last_synced_at timestamp with time zone,
    last_sync_failure character varying(255),
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_state smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_1886652634 CHECK ((char_length(verification_failure) <= 256)),
    CONSTRAINT check_8cc7c5aee5 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_b1405efadb CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE file_registry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE file_registry_id_seq OWNED BY file_registry.id;

CREATE TABLE group_upload_registry (
    id bigint NOT NULL,
    group_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_3f4ba66676 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_73978a7389 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_93eb766854 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_c67c0e9c61 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE group_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE group_upload_registry_id_seq OWNED BY group_upload_registry.id;

CREATE TABLE group_wiki_repository_registry (
    id bigint NOT NULL,
    retry_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    group_wiki_repository_id bigint NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0,
    last_sync_failure text,
    missing_on_primary boolean,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_state smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    CONSTRAINT check_0a6e7bc04a CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE group_wiki_repository_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE group_wiki_repository_registry_id_seq OWNED BY group_wiki_repository_registry.id;

CREATE TABLE import_export_upload_upload_registry (
    id bigint NOT NULL,
    import_export_upload_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_4276268677 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_8fb4aefa36 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_c23968fde1 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_d9451d68c6 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE import_export_upload_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE import_export_upload_upload_registry_id_seq OWNED BY import_export_upload_upload_registry.id;

CREATE TABLE issuable_metric_image_upload_registry (
    id bigint NOT NULL,
    issuable_metric_image_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_14b9fdbfb1 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_b5b6aba2b2 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_c396a26e8b CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_c46acb7c19 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE issuable_metric_image_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE issuable_metric_image_upload_registry_id_seq OWNED BY issuable_metric_image_upload_registry.id;

CREATE TABLE job_artifact_registry (
    id integer NOT NULL,
    created_at timestamp with time zone,
    retry_at timestamp with time zone,
    bytes bigint,
    artifact_id integer,
    retry_count integer DEFAULT 0,
    sha256 character varying,
    missing_on_primary boolean DEFAULT false NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    last_synced_at timestamp with time zone,
    last_sync_failure character varying(255),
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_state smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_failure character varying(255),
    blob_path text,
    CONSTRAINT check_91faba8ae2 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE job_artifact_registry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE job_artifact_registry_id_seq OWNED BY job_artifact_registry.id;

CREATE TABLE lfs_object_registry (
    id bigint NOT NULL,
    created_at timestamp with time zone,
    retry_at timestamp with time zone,
    bytes bigint,
    lfs_object_id integer,
    retry_count integer DEFAULT 0,
    missing_on_primary boolean DEFAULT false NOT NULL,
    success boolean DEFAULT false NOT NULL,
    sha256 bytea,
    state smallint DEFAULT 0 NOT NULL,
    last_synced_at timestamp with time zone,
    last_sync_failure text,
    verification_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_retry_count integer DEFAULT 0,
    verification_state smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    blob_path text,
    CONSTRAINT check_251f787681 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_8bcaa12138 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE lfs_object_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE lfs_object_registry_id_seq OWNED BY lfs_object_registry.id;

CREATE TABLE merge_request_diff_registry (
    id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    retry_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    merge_request_diff_id bigint NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0,
    last_sync_failure text,
    verification_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_retry_count integer,
    verification_state smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure character varying(255),
    blob_path text,
    CONSTRAINT check_5b35c4ed1d CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE merge_request_diff_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE merge_request_diff_registry_id_seq OWNED BY merge_request_diff_registry.id;

CREATE TABLE organization_detail_upload_registry (
    id bigint NOT NULL,
    organization_detail_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_41ddf26cd0 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_d3bf810d54 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_de2f46c536 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_f4e578df05 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE organization_detail_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE organization_detail_upload_registry_id_seq OWNED BY organization_detail_upload_registry.id;

CREATE TABLE package_file_registry (
    id integer NOT NULL,
    package_file_id integer NOT NULL,
    state integer DEFAULT 0 NOT NULL,
    retry_count integer DEFAULT 0,
    last_sync_failure character varying(255),
    retry_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    verification_failure character varying(255),
    verification_checksum bytea,
    checksum_mismatch boolean,
    verification_checksum_mismatched bytea,
    verification_retry_count integer,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_state smallint DEFAULT 0 NOT NULL,
    verification_started_at timestamp with time zone,
    blob_path text,
    CONSTRAINT check_baa17458d1 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE package_file_registry_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE package_file_registry_id_seq OWNED BY package_file_registry.id;

CREATE TABLE packages_debian_project_component_file_registry (
    id bigint NOT NULL,
    packages_debian_project_component_file_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_2ef314d0a7 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_3a31e36a4c CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_b87464fbfe CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE packages_debian_project_component_file_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE packages_debian_project_component_file_registry_id_seq OWNED BY packages_debian_project_component_file_registry.id;

CREATE TABLE packages_helm_metadata_cache_registry (
    id bigint NOT NULL,
    packages_helm_metadata_cache_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_692956eb3c CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_f0c64ec7fd CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_fdce76cea0 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE packages_helm_metadata_cache_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE packages_helm_metadata_cache_registry_id_seq OWNED BY packages_helm_metadata_cache_registry.id;

CREATE TABLE packages_nuget_symbol_registry (
    id bigint NOT NULL,
    packages_nuget_symbol_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_353acf9c46 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_4b08fc53d8 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_6c64bdb976 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE packages_nuget_symbol_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE packages_nuget_symbol_registry_id_seq OWNED BY packages_nuget_symbol_registry.id;

CREATE TABLE pages_deployment_registry (
    id bigint NOT NULL,
    pages_deployment_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    last_sync_failure character varying(255),
    verification_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    blob_path text,
    CONSTRAINT check_06c347e437 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_7eb0430eff CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE pages_deployment_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE pages_deployment_registry_id_seq OWNED BY pages_deployment_registry.id;

CREATE TABLE personal_snippet_upload_registry (
    id bigint NOT NULL,
    personal_snippet_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_8a297a0234 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_9796933c30 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_c002a1bc04 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_e2ec7cf64a CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE personal_snippet_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE personal_snippet_upload_registry_id_seq OWNED BY personal_snippet_upload_registry.id;

CREATE TABLE pipeline_artifact_registry (
    id bigint NOT NULL,
    pipeline_artifact_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0,
    verification_retry_count smallint DEFAULT 0,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure character varying(255),
    last_sync_failure character varying(255),
    blob_path text,
    CONSTRAINT check_23c2939591 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE pipeline_artifact_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE pipeline_artifact_registry_id_seq OWNED BY pipeline_artifact_registry.id;

CREATE TABLE project_import_export_relation_export_upload_upload_registry (
    id bigint NOT NULL,
    project_import_export_relation_export_upload_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_2bb59c3d8f CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_6bc4c3d349 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_c3ef59c9ca CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_fa50035ba7 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE project_import_export_relation_export_upload_upload_regi_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE project_import_export_relation_export_upload_upload_regi_id_seq OWNED BY project_import_export_relation_export_upload_upload_registry.id;

CREATE TABLE project_repository_registry (
    id bigint NOT NULL,
    project_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    missing_on_primary boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    project_repository_id bigint,
    CONSTRAINT check_45b82eebee CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_58aa799387 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE project_repository_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE project_repository_registry_id_seq OWNED BY project_repository_registry.id;

CREATE TABLE project_topic_upload_registry (
    id bigint NOT NULL,
    project_topic_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_6a262bdef7 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_bb14d27775 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_bc88b8d8ba CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_e0ca0d5703 CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE project_topic_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE project_topic_upload_registry_id_seq OWNED BY project_topic_upload_registry.id;

CREATE TABLE project_upload_registry (
    id bigint NOT NULL,
    project_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_3cfc848d98 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_5e9e57915f CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_aed304e9e0 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_e01baaf255 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE project_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE project_upload_registry_id_seq OWNED BY project_upload_registry.id;

CREATE TABLE project_wiki_repository_registry (
    id bigint NOT NULL,
    project_id bigint,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    missing_on_primary boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    project_wiki_repository_id bigint,
    CONSTRAINT check_038a3a8139 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_33007d5eb2 CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE project_wiki_repository_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE project_wiki_repository_registry_id_seq OWNED BY project_wiki_repository_registry.id;

CREATE TABLE schema_migrations (
    version character varying NOT NULL
);

CREATE TABLE secondary_usage_data (
    id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL
);

CREATE SEQUENCE secondary_usage_data_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE secondary_usage_data_id_seq OWNED BY secondary_usage_data.id;

CREATE TABLE snippet_repository_registry (
    id bigint NOT NULL,
    retry_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    snippet_repository_id bigint NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0,
    last_sync_failure text,
    missing_on_primary boolean,
    verification_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_retry_count integer,
    verification_state smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure character varying(255)
);

CREATE SEQUENCE snippet_repository_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE snippet_repository_registry_id_seq OWNED BY snippet_repository_registry.id;

CREATE TABLE supply_chain_attestation_registry (
    id bigint NOT NULL,
    supply_chain_attestation_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_70b27e12c6 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_70bd67f7e6 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_83facb720c CHECK ((char_length(last_sync_failure) <= 255))
);

CREATE SEQUENCE supply_chain_attestation_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE supply_chain_attestation_registry_id_seq OWNED BY supply_chain_attestation_registry.id;

CREATE TABLE terraform_state_version_registry (
    id bigint NOT NULL,
    terraform_state_version_id bigint NOT NULL,
    state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    retry_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    last_sync_failure text,
    verification_started_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    verification_retry_count integer DEFAULT 0,
    verification_state smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure character varying(255),
    blob_path text,
    CONSTRAINT check_f93b1197e5 CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE terraform_state_version_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE terraform_state_version_registry_id_seq OWNED BY terraform_state_version_registry.id;

CREATE TABLE user_permission_export_upload_upload_registry (
    id bigint NOT NULL,
    user_permission_export_upload_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_24b19f311a CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_3aa1bc141c CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_cc83fad07a CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_ed827154ce CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE user_permission_export_upload_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE user_permission_export_upload_upload_registry_id_seq OWNED BY user_permission_export_upload_upload_registry.id;

CREATE TABLE user_upload_registry (
    id bigint NOT NULL,
    user_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_119ab7beb4 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_54902ff286 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_a560aaad8b CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_d5b421b5c4 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE user_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE user_upload_registry_id_seq OWNED BY user_upload_registry.id;

CREATE TABLE virtual_registries_packages_maven_cache_remote_entry_registry (
    id bigint NOT NULL,
    virtual_registries_packages_maven_cache_remote_entry_iid bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    CONSTRAINT check_30504a8e67 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_31fdc9a498 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_544b18f26a CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE virtual_registries_packages_maven_cache_remote_entry_reg_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE virtual_registries_packages_maven_cache_remote_entry_reg_id_seq OWNED BY virtual_registries_packages_maven_cache_remote_entry_registry.id;

CREATE TABLE vulnerability_archive_export_upload_registry (
    id bigint NOT NULL,
    vulnerability_archive_export_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_30a10d4fdb CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_810c705cf5 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_83d20425aa CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_8c785dd51a CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE vulnerability_archive_export_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE vulnerability_archive_export_upload_registry_id_seq OWNED BY vulnerability_archive_export_upload_registry.id;

CREATE TABLE vulnerability_export_part_upload_registry (
    id bigint NOT NULL,
    vulnerability_export_part_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_4081858da3 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_4b5fbfcc91 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_940f13dfcc CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_d164e047af CHECK ((char_length(verification_failure) <= 255))
);

CREATE SEQUENCE vulnerability_export_part_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE vulnerability_export_part_upload_registry_id_seq OWNED BY vulnerability_export_part_upload_registry.id;

CREATE TABLE vulnerability_export_upload_registry (
    id bigint NOT NULL,
    vulnerability_export_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_7cbbf54418 CHECK ((char_length(uploader_class) <= 255)),
    CONSTRAINT check_7eb093d5c8 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_8c33102b2c CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_e25006f4ce CHECK ((char_length(blob_path) <= 1024))
);

CREATE SEQUENCE vulnerability_export_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE vulnerability_export_upload_registry_id_seq OWNED BY vulnerability_export_upload_registry.id;

CREATE TABLE vulnerability_remediation_upload_registry (
    id bigint NOT NULL,
    vulnerability_remediation_upload_id bigint NOT NULL,
    created_at timestamp with time zone NOT NULL,
    last_synced_at timestamp with time zone,
    retry_at timestamp with time zone,
    verified_at timestamp with time zone,
    verification_started_at timestamp with time zone,
    verification_retry_at timestamp with time zone,
    state smallint DEFAULT 0 NOT NULL,
    verification_state smallint DEFAULT 0 NOT NULL,
    retry_count smallint DEFAULT 0 NOT NULL,
    verification_retry_count smallint DEFAULT 0 NOT NULL,
    checksum_mismatch boolean DEFAULT false NOT NULL,
    verification_checksum bytea,
    verification_checksum_mismatched bytea,
    verification_failure text,
    last_sync_failure text,
    blob_path text,
    uploader_class text,
    CONSTRAINT check_4a38858aa9 CHECK ((char_length(verification_failure) <= 255)),
    CONSTRAINT check_4d835f3e92 CHECK ((char_length(last_sync_failure) <= 255)),
    CONSTRAINT check_6d3d4a2440 CHECK ((char_length(blob_path) <= 1024)),
    CONSTRAINT check_b62e8243a2 CHECK ((char_length(uploader_class) <= 255))
);

CREATE SEQUENCE vulnerability_remediation_upload_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE vulnerability_remediation_upload_registry_id_seq OWNED BY vulnerability_remediation_upload_registry.id;

ALTER TABLE ONLY abuse_report_upload_registry ALTER COLUMN id SET DEFAULT nextval('abuse_report_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY achievement_upload_registry ALTER COLUMN id SET DEFAULT nextval('achievement_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY ai_vectorizable_file_upload_registry ALTER COLUMN id SET DEFAULT nextval('ai_vectorizable_file_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY alert_management_metric_image_upload_registry ALTER COLUMN id SET DEFAULT nextval('alert_management_metric_image_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY appearance_upload_registry ALTER COLUMN id SET DEFAULT nextval('appearance_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY bulk_import_export_upload_upload_registry ALTER COLUMN id SET DEFAULT nextval('bulk_import_export_upload_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY ci_secure_file_registry ALTER COLUMN id SET DEFAULT nextval('ci_secure_file_registry_id_seq'::regclass);

ALTER TABLE ONLY container_repository_registry ALTER COLUMN id SET DEFAULT nextval('container_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY dependency_list_export_part_upload_registry ALTER COLUMN id SET DEFAULT nextval('dependency_list_export_part_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY dependency_list_export_upload_registry ALTER COLUMN id SET DEFAULT nextval('dependency_list_export_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY dependency_proxy_blob_registry ALTER COLUMN id SET DEFAULT nextval('dependency_proxy_blob_registry_id_seq'::regclass);

ALTER TABLE ONLY dependency_proxy_manifest_registry ALTER COLUMN id SET DEFAULT nextval('dependency_proxy_manifest_registry_id_seq'::regclass);

ALTER TABLE ONLY design_management_action_upload_registry ALTER COLUMN id SET DEFAULT nextval('design_management_action_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY design_management_repository_registry ALTER COLUMN id SET DEFAULT nextval('design_management_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY event_log_states ALTER COLUMN event_id SET DEFAULT nextval('event_log_states_event_id_seq'::regclass);

ALTER TABLE ONLY file_registry ALTER COLUMN id SET DEFAULT nextval('file_registry_id_seq'::regclass);

ALTER TABLE ONLY group_upload_registry ALTER COLUMN id SET DEFAULT nextval('group_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY group_wiki_repository_registry ALTER COLUMN id SET DEFAULT nextval('group_wiki_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY import_export_upload_upload_registry ALTER COLUMN id SET DEFAULT nextval('import_export_upload_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY issuable_metric_image_upload_registry ALTER COLUMN id SET DEFAULT nextval('issuable_metric_image_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY job_artifact_registry ALTER COLUMN id SET DEFAULT nextval('job_artifact_registry_id_seq'::regclass);

ALTER TABLE ONLY lfs_object_registry ALTER COLUMN id SET DEFAULT nextval('lfs_object_registry_id_seq'::regclass);

ALTER TABLE ONLY merge_request_diff_registry ALTER COLUMN id SET DEFAULT nextval('merge_request_diff_registry_id_seq'::regclass);

ALTER TABLE ONLY organization_detail_upload_registry ALTER COLUMN id SET DEFAULT nextval('organization_detail_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY package_file_registry ALTER COLUMN id SET DEFAULT nextval('package_file_registry_id_seq'::regclass);

ALTER TABLE ONLY packages_debian_project_component_file_registry ALTER COLUMN id SET DEFAULT nextval('packages_debian_project_component_file_registry_id_seq'::regclass);

ALTER TABLE ONLY packages_helm_metadata_cache_registry ALTER COLUMN id SET DEFAULT nextval('packages_helm_metadata_cache_registry_id_seq'::regclass);

ALTER TABLE ONLY packages_nuget_symbol_registry ALTER COLUMN id SET DEFAULT nextval('packages_nuget_symbol_registry_id_seq'::regclass);

ALTER TABLE ONLY pages_deployment_registry ALTER COLUMN id SET DEFAULT nextval('pages_deployment_registry_id_seq'::regclass);

ALTER TABLE ONLY personal_snippet_upload_registry ALTER COLUMN id SET DEFAULT nextval('personal_snippet_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY pipeline_artifact_registry ALTER COLUMN id SET DEFAULT nextval('pipeline_artifact_registry_id_seq'::regclass);

ALTER TABLE ONLY project_import_export_relation_export_upload_upload_registry ALTER COLUMN id SET DEFAULT nextval('project_import_export_relation_export_upload_upload_regi_id_seq'::regclass);

ALTER TABLE ONLY project_repository_registry ALTER COLUMN id SET DEFAULT nextval('project_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY project_topic_upload_registry ALTER COLUMN id SET DEFAULT nextval('project_topic_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY project_upload_registry ALTER COLUMN id SET DEFAULT nextval('project_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY project_wiki_repository_registry ALTER COLUMN id SET DEFAULT nextval('project_wiki_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY secondary_usage_data ALTER COLUMN id SET DEFAULT nextval('secondary_usage_data_id_seq'::regclass);

ALTER TABLE ONLY snippet_repository_registry ALTER COLUMN id SET DEFAULT nextval('snippet_repository_registry_id_seq'::regclass);

ALTER TABLE ONLY supply_chain_attestation_registry ALTER COLUMN id SET DEFAULT nextval('supply_chain_attestation_registry_id_seq'::regclass);

ALTER TABLE ONLY terraform_state_version_registry ALTER COLUMN id SET DEFAULT nextval('terraform_state_version_registry_id_seq'::regclass);

ALTER TABLE ONLY user_permission_export_upload_upload_registry ALTER COLUMN id SET DEFAULT nextval('user_permission_export_upload_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY user_upload_registry ALTER COLUMN id SET DEFAULT nextval('user_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY virtual_registries_packages_maven_cache_remote_entry_registry ALTER COLUMN id SET DEFAULT nextval('virtual_registries_packages_maven_cache_remote_entry_reg_id_seq'::regclass);

ALTER TABLE ONLY vulnerability_archive_export_upload_registry ALTER COLUMN id SET DEFAULT nextval('vulnerability_archive_export_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY vulnerability_export_part_upload_registry ALTER COLUMN id SET DEFAULT nextval('vulnerability_export_part_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY vulnerability_export_upload_registry ALTER COLUMN id SET DEFAULT nextval('vulnerability_export_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY vulnerability_remediation_upload_registry ALTER COLUMN id SET DEFAULT nextval('vulnerability_remediation_upload_registry_id_seq'::regclass);

ALTER TABLE ONLY abuse_report_upload_registry
    ADD CONSTRAINT abuse_report_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY achievement_upload_registry
    ADD CONSTRAINT achievement_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ai_vectorizable_file_upload_registry
    ADD CONSTRAINT ai_vectorizable_file_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY alert_management_metric_image_upload_registry
    ADD CONSTRAINT alert_management_metric_image_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY appearance_upload_registry
    ADD CONSTRAINT appearance_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY ar_internal_metadata
    ADD CONSTRAINT ar_internal_metadata_pkey PRIMARY KEY (key);

ALTER TABLE ONLY bulk_import_export_upload_upload_registry
    ADD CONSTRAINT bulk_import_export_upload_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE project_wiki_repository_registry
    ADD CONSTRAINT check_4112c47225 CHECK ((project_wiki_repository_id IS NOT NULL)) NOT VALID;

ALTER TABLE ONLY ci_secure_file_registry
    ADD CONSTRAINT ci_secure_file_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY container_repository_registry
    ADD CONSTRAINT container_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dependency_list_export_part_upload_registry
    ADD CONSTRAINT dependency_list_export_part_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dependency_list_export_upload_registry
    ADD CONSTRAINT dependency_list_export_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dependency_proxy_blob_registry
    ADD CONSTRAINT dependency_proxy_blob_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY dependency_proxy_manifest_registry
    ADD CONSTRAINT dependency_proxy_manifest_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY design_management_action_upload_registry
    ADD CONSTRAINT design_management_action_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY design_management_repository_registry
    ADD CONSTRAINT design_management_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY event_log_states
    ADD CONSTRAINT event_log_states_pkey PRIMARY KEY (event_id);

ALTER TABLE ONLY file_registry
    ADD CONSTRAINT file_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY group_upload_registry
    ADD CONSTRAINT group_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY group_wiki_repository_registry
    ADD CONSTRAINT group_wiki_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY import_export_upload_upload_registry
    ADD CONSTRAINT import_export_upload_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY issuable_metric_image_upload_registry
    ADD CONSTRAINT issuable_metric_image_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY job_artifact_registry
    ADD CONSTRAINT job_artifact_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY lfs_object_registry
    ADD CONSTRAINT lfs_object_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY merge_request_diff_registry
    ADD CONSTRAINT merge_request_diff_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY organization_detail_upload_registry
    ADD CONSTRAINT organization_detail_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY package_file_registry
    ADD CONSTRAINT package_file_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY packages_debian_project_component_file_registry
    ADD CONSTRAINT packages_debian_project_component_file_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY packages_helm_metadata_cache_registry
    ADD CONSTRAINT packages_helm_metadata_cache_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY packages_nuget_symbol_registry
    ADD CONSTRAINT packages_nuget_symbol_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY pages_deployment_registry
    ADD CONSTRAINT pages_deployment_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY personal_snippet_upload_registry
    ADD CONSTRAINT personal_snippet_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY pipeline_artifact_registry
    ADD CONSTRAINT pipeline_artifact_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY project_import_export_relation_export_upload_upload_registry
    ADD CONSTRAINT project_import_export_relation_export_upload_upload_regist_pkey PRIMARY KEY (id);

ALTER TABLE ONLY project_repository_registry
    ADD CONSTRAINT project_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY project_topic_upload_registry
    ADD CONSTRAINT project_topic_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY project_upload_registry
    ADD CONSTRAINT project_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY project_wiki_repository_registry
    ADD CONSTRAINT project_wiki_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);

ALTER TABLE ONLY secondary_usage_data
    ADD CONSTRAINT secondary_usage_data_pkey PRIMARY KEY (id);

ALTER TABLE ONLY snippet_repository_registry
    ADD CONSTRAINT snippet_repository_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY supply_chain_attestation_registry
    ADD CONSTRAINT supply_chain_attestation_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY terraform_state_version_registry
    ADD CONSTRAINT terraform_state_version_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_permission_export_upload_upload_registry
    ADD CONSTRAINT user_permission_export_upload_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY user_upload_registry
    ADD CONSTRAINT user_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY virtual_registries_packages_maven_cache_remote_entry_registry
    ADD CONSTRAINT virtual_registries_packages_maven_cache_remote_entry_regis_pkey PRIMARY KEY (id);

ALTER TABLE ONLY vulnerability_archive_export_upload_registry
    ADD CONSTRAINT vulnerability_archive_export_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY vulnerability_export_part_upload_registry
    ADD CONSTRAINT vulnerability_export_part_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY vulnerability_export_upload_registry
    ADD CONSTRAINT vulnerability_export_upload_registry_pkey PRIMARY KEY (id);

ALTER TABLE ONLY vulnerability_remediation_upload_registry
    ADD CONSTRAINT vulnerability_remediation_upload_registry_pkey PRIMARY KEY (id);

CREATE INDEX abuse_report_upload_registry_failed_verification ON abuse_report_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX abuse_report_upload_registry_needs_verification ON abuse_report_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX abuse_report_upload_registry_pending_verification ON abuse_report_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX achievement_upload_registry_failed_verification ON achievement_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX achievement_upload_registry_needs_verification ON achievement_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX achievement_upload_registry_pending_verification ON achievement_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX ai_vectorizable_file_upload_registry_failed_verification ON ai_vectorizable_file_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX ai_vectorizable_file_upload_registry_needs_verification ON ai_vectorizable_file_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX ai_vectorizable_file_upload_registry_pending_verification ON ai_vectorizable_file_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX appearance_upload_registry_failed_verification ON appearance_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX appearance_upload_registry_needs_verification ON appearance_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX appearance_upload_registry_pending_verification ON appearance_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX ci_secure_file_registry_failed_verification ON ci_secure_file_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX ci_secure_file_registry_needs_verification ON ci_secure_file_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX ci_secure_file_registry_pending_verification ON ci_secure_file_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX container_repository_registry_failed_verification ON container_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE (verification_state = 3);

CREATE INDEX container_repository_registry_needs_verification ON container_repository_registry USING btree (verification_state) WHERE (verification_state = ANY (ARRAY[0, 3]));

CREATE INDEX container_repository_registry_pending_verification ON container_repository_registry USING btree (verified_at NULLS FIRST) WHERE (verification_state = 0);

CREATE INDEX dependency_proxy_blob_registry_failed_verification ON dependency_proxy_blob_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX dependency_proxy_blob_registry_needs_verification ON dependency_proxy_blob_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX dependency_proxy_blob_registry_pending_verification ON dependency_proxy_blob_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX dependency_proxy_manifest_registry_failed_verification ON dependency_proxy_manifest_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX dependency_proxy_manifest_registry_needs_verification ON dependency_proxy_manifest_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX dependency_proxy_manifest_registry_pending_verification ON dependency_proxy_manifest_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX design_management_action_upload_registry_failed_verification ON design_management_action_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX design_management_action_upload_registry_needs_verification ON design_management_action_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX design_management_action_upload_registry_pending_verification ON design_management_action_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX design_management_repository_registry_failed_verification ON design_management_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX design_management_repository_registry_needs_verification ON design_management_repository_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX design_management_repository_registry_pending_verification ON design_management_repository_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX file_registry_failed_verification ON file_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX file_registry_needs_verification ON file_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX file_registry_pending_verification ON file_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX group_upload_registry_failed_verification ON group_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX group_upload_registry_needs_verification ON group_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX group_upload_registry_pending_verification ON group_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX group_wiki_repository_registry_failed_verification ON group_wiki_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE (verification_state = 3);

CREATE INDEX group_wiki_repository_registry_needs_verification ON group_wiki_repository_registry USING btree (verification_state) WHERE (verification_state = ANY (ARRAY[0, 3]));

CREATE INDEX group_wiki_repository_registry_pending_verification ON group_wiki_repository_registry USING btree (verified_at NULLS FIRST) WHERE (verification_state = 0);

CREATE UNIQUE INDEX i_dependency_proxy_blob_registry_on_dependency_proxy_blob_id ON dependency_proxy_blob_registry USING btree (dependency_proxy_blob_id);

CREATE UNIQUE INDEX idx_ai_vectorizable_file_upload_registry_on_upload_id ON ai_vectorizable_file_upload_registry USING btree (ai_vectorizable_file_upload_id);

CREATE INDEX idx_amm_upload_registry_failed_verification ON alert_management_metric_image_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_amm_upload_registry_needs_verification ON alert_management_metric_image_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_amm_upload_registry_on_amm_upload_id ON alert_management_metric_image_upload_registry USING btree (alert_management_metric_image_upload_id);

CREATE INDEX idx_amm_upload_registry_pending_verification ON alert_management_metric_image_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_bie_upl_upl_registry_failed_verification ON bulk_import_export_upload_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_bie_upl_upl_registry_needs_verification ON bulk_import_export_upload_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_bie_upl_upl_registry_on_bie_upl_upl_id ON bulk_import_export_upload_upload_registry USING btree (bulk_import_export_upload_upload_id);

CREATE INDEX idx_bie_upl_upl_registry_pending_verification ON bulk_import_export_upload_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE UNIQUE INDEX idx_design_management_action_upload_registry_on_upload_id ON design_management_action_upload_registry USING btree (design_management_action_upload_id);

CREATE INDEX idx_dle_upl_registry_failed_verification ON dependency_list_export_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_dle_upl_registry_needs_verification ON dependency_list_export_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_dle_upl_registry_on_dle_upl_id ON dependency_list_export_upload_registry USING btree (dependency_list_export_upload_id);

CREATE INDEX idx_dle_upl_registry_pending_verification ON dependency_list_export_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_dlep_upl_registry_failed_verification ON dependency_list_export_part_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_dlep_upl_registry_needs_verification ON dependency_list_export_part_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_dlep_upl_registry_on_dlep_upl_id ON dependency_list_export_part_upload_registry USING btree (dependency_list_export_part_upload_id);

CREATE INDEX idx_dlep_upl_registry_pending_verification ON dependency_list_export_part_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE UNIQUE INDEX idx_import_export_upload_upload_registry_on_upload_id ON import_export_upload_upload_registry USING btree (import_export_upload_upload_id);

CREATE INDEX idx_od_upl_registry_failed_verification ON organization_detail_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_od_upl_registry_needs_verification ON organization_detail_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_od_upl_registry_on_od_upl_id ON organization_detail_upload_registry USING btree (organization_detail_upload_id);

CREATE INDEX idx_od_upl_registry_pending_verification ON organization_detail_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE UNIQUE INDEX idx_piere_upload_upload_registry_on_piere_upload_upload_id ON project_import_export_relation_export_upload_upload_registry USING btree (project_import_export_relation_export_upload_upload_id);

CREATE UNIQUE INDEX idx_pkgs_helm_metadata_cache_registry_on_metadata_cache_id ON packages_helm_metadata_cache_registry USING btree (packages_helm_metadata_cache_id);

CREATE UNIQUE INDEX idx_project_wiki_repository_registry_project_wiki_repository_id ON project_wiki_repository_registry USING btree (project_wiki_repository_id);

CREATE INDEX idx_user_permission_export_upload_registry_failed_verification ON user_permission_export_upload_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_user_permission_export_upload_registry_needs_verification ON user_permission_export_upload_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX idx_user_permission_export_upload_registry_on_retry_at ON user_permission_export_upload_upload_registry USING btree (retry_at);

CREATE INDEX idx_user_permission_export_upload_registry_on_state ON user_permission_export_upload_upload_registry USING btree (state);

CREATE UNIQUE INDEX idx_user_permission_export_upload_registry_on_upe_upload_id ON user_permission_export_upload_upload_registry USING btree (user_permission_export_upload_upload_id);

CREATE INDEX idx_user_permission_export_upload_registry_pending_verification ON user_permission_export_upload_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_vae_upl_registry_failed_verification ON vulnerability_archive_export_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_vae_upl_registry_needs_verification ON vulnerability_archive_export_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_vae_upl_registry_on_vae_upl_id ON vulnerability_archive_export_upload_registry USING btree (vulnerability_archive_export_upload_id);

CREATE INDEX idx_vae_upl_registry_pending_verification ON vulnerability_archive_export_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_ve_upl_registry_failed_verification ON vulnerability_export_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_ve_upl_registry_needs_verification ON vulnerability_export_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_ve_upl_registry_on_ve_upl_id ON vulnerability_export_upload_registry USING btree (vulnerability_export_upload_id);

CREATE INDEX idx_ve_upl_registry_pending_verification ON vulnerability_export_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_vep_upl_registry_failed_verification ON vulnerability_export_part_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_vep_upl_registry_needs_verification ON vulnerability_export_part_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_vep_upl_registry_on_vep_upl_id ON vulnerability_export_part_upload_registry USING btree (vulnerability_export_part_upload_id);

CREATE INDEX idx_vep_upl_registry_pending_verification ON vulnerability_export_part_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX idx_vreg_mvn_cache_remote_registry_failed_verification ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX idx_vreg_mvn_cache_remote_registry_needs_verification ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE UNIQUE INDEX idx_vreg_mvn_cache_remote_registry_on_entry_iid ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (virtual_registries_packages_maven_cache_remote_entry_iid);

CREATE INDEX idx_vreg_mvn_cache_remote_registry_on_retry_at ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (retry_at);

CREATE INDEX idx_vreg_mvn_cache_remote_registry_on_state ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (state);

CREATE INDEX idx_vreg_mvn_cache_remote_registry_pending_verification ON virtual_registries_packages_maven_cache_remote_entry_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX import_export_upload_upload_registry_failed_verification ON import_export_upload_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX import_export_upload_upload_registry_needs_verification ON import_export_upload_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX import_export_upload_upload_registry_pending_verification ON import_export_upload_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE UNIQUE INDEX index_abuse_report_upload_registry_on_abuse_report_upload_id ON abuse_report_upload_registry USING btree (abuse_report_upload_id);

CREATE INDEX index_abuse_report_upload_registry_on_retry_at ON abuse_report_upload_registry USING btree (retry_at);

CREATE INDEX index_abuse_report_upload_registry_on_state ON abuse_report_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_achievement_upload_registry_on_achievement_upload_id ON achievement_upload_registry USING btree (achievement_upload_id);

CREATE INDEX index_achievement_upload_registry_on_retry_at ON achievement_upload_registry USING btree (retry_at);

CREATE INDEX index_achievement_upload_registry_on_state ON achievement_upload_registry USING btree (state);

CREATE INDEX index_ai_vectorizable_file_upload_registry_on_retry_at ON ai_vectorizable_file_upload_registry USING btree (retry_at);

CREATE INDEX index_ai_vectorizable_file_upload_registry_on_state ON ai_vectorizable_file_upload_registry USING btree (state);

CREATE INDEX index_alert_management_metric_image_upload_registry_on_retry_at ON alert_management_metric_image_upload_registry USING btree (retry_at);

CREATE INDEX index_alert_management_metric_image_upload_registry_on_state ON alert_management_metric_image_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_appearance_upload_registry_on_appearance_upload_id ON appearance_upload_registry USING btree (appearance_upload_id);

CREATE INDEX index_appearance_upload_registry_on_retry_at ON appearance_upload_registry USING btree (retry_at);

CREATE INDEX index_appearance_upload_registry_on_state ON appearance_upload_registry USING btree (state);

CREATE INDEX index_bulk_import_export_upload_upload_registry_on_retry_at ON bulk_import_export_upload_upload_registry USING btree (retry_at);

CREATE INDEX index_bulk_import_export_upload_upload_registry_on_state ON bulk_import_export_upload_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_ci_secure_file_registry_on_ci_secure_file_id ON ci_secure_file_registry USING btree (ci_secure_file_id);

CREATE INDEX index_ci_secure_file_registry_on_last_synced_at ON ci_secure_file_registry USING btree (last_synced_at);

CREATE INDEX index_ci_secure_file_registry_on_retry_at ON ci_secure_file_registry USING btree (retry_at);

CREATE INDEX index_ci_secure_file_registry_on_state ON ci_secure_file_registry USING btree (state);

CREATE INDEX index_ci_secure_file_registry_on_verified_at ON ci_secure_file_registry USING btree (verified_at);

CREATE INDEX index_container_repository_registry_on_last_synced_at ON container_repository_registry USING btree (last_synced_at);

CREATE INDEX index_container_repository_registry_on_retry_at ON container_repository_registry USING btree (retry_at);

CREATE INDEX index_container_repository_registry_on_state ON container_repository_registry USING btree (state);

CREATE INDEX index_container_repository_registry_on_verified_at ON container_repository_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_container_repository_registry_repository_id_unique ON container_repository_registry USING btree (container_repository_id);

CREATE INDEX index_dependency_list_export_part_upload_registry_on_retry_at ON dependency_list_export_part_upload_registry USING btree (retry_at);

CREATE INDEX index_dependency_list_export_part_upload_registry_on_state ON dependency_list_export_part_upload_registry USING btree (state);

CREATE INDEX index_dependency_list_export_upload_registry_on_retry_at ON dependency_list_export_upload_registry USING btree (retry_at);

CREATE INDEX index_dependency_list_export_upload_registry_on_state ON dependency_list_export_upload_registry USING btree (state);

CREATE INDEX index_dependency_proxy_blob_registry_on_last_synced_at ON dependency_proxy_blob_registry USING btree (last_synced_at);

CREATE INDEX index_dependency_proxy_blob_registry_on_retry_at ON dependency_proxy_blob_registry USING btree (retry_at);

CREATE INDEX index_dependency_proxy_blob_registry_on_state ON dependency_proxy_blob_registry USING btree (state);

CREATE INDEX index_dependency_proxy_blob_registry_on_verified_at ON dependency_proxy_blob_registry USING btree (verified_at);

CREATE INDEX index_dependency_proxy_manifest_registry_on_last_synced_at ON dependency_proxy_manifest_registry USING btree (last_synced_at);

CREATE INDEX index_dependency_proxy_manifest_registry_on_retry_at ON dependency_proxy_manifest_registry USING btree (retry_at);

CREATE INDEX index_dependency_proxy_manifest_registry_on_state ON dependency_proxy_manifest_registry USING btree (state);

CREATE INDEX index_dependency_proxy_manifest_registry_on_verified_at ON dependency_proxy_manifest_registry USING btree (verified_at);

CREATE INDEX index_design_management_action_upload_registry_on_retry_at ON design_management_action_upload_registry USING btree (retry_at);

CREATE INDEX index_design_management_action_upload_registry_on_state ON design_management_action_upload_registry USING btree (state);

CREATE INDEX index_design_management_repository_registry_checksum_mismatch ON design_management_repository_registry USING btree (verification_retry_at) WHERE (checksum_mismatch = true);

CREATE INDEX index_design_management_repository_registry_on_last_synced_at ON design_management_repository_registry USING btree (last_synced_at);

CREATE INDEX index_design_management_repository_registry_on_retry_at ON design_management_repository_registry USING btree (retry_at);

CREATE INDEX index_design_management_repository_registry_on_state ON design_management_repository_registry USING btree (state);

CREATE INDEX index_design_management_repository_registry_on_verified_at ON design_management_repository_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_design_repo_registry_on_design_repo_id ON design_management_repository_registry USING btree (design_management_repository_id);

CREATE UNIQUE INDEX index_file_registry_on_file_id_unique ON file_registry USING btree (file_id);

CREATE INDEX index_file_registry_on_last_synced_at ON file_registry USING btree (last_synced_at);

CREATE INDEX index_file_registry_on_retry_at ON file_registry USING btree (retry_at);

CREATE INDEX index_file_registry_on_verified_at ON file_registry USING btree (verified_at);

CREATE INDEX index_file_registry_state ON file_registry USING btree (state);

CREATE UNIQUE INDEX index_g_wiki_repository_registry_on_group_wiki_repository_id ON group_wiki_repository_registry USING btree (group_wiki_repository_id);

CREATE UNIQUE INDEX index_group_upload_registry_on_group_upload_id ON group_upload_registry USING btree (group_upload_id);

CREATE INDEX index_group_upload_registry_on_retry_at ON group_upload_registry USING btree (retry_at);

CREATE INDEX index_group_upload_registry_on_state ON group_upload_registry USING btree (state);

CREATE INDEX index_group_wiki_repository_registry_checksum_mismatch ON group_wiki_repository_registry USING btree (verification_retry_at) WHERE (checksum_mismatch = true);

CREATE INDEX index_group_wiki_repository_registry_on_last_synced_at ON group_wiki_repository_registry USING btree (last_synced_at);

CREATE INDEX index_group_wiki_repository_registry_on_retry_at ON group_wiki_repository_registry USING btree (retry_at);

CREATE INDEX index_group_wiki_repository_registry_on_state ON group_wiki_repository_registry USING btree (state);

CREATE INDEX index_group_wiki_repository_registry_on_verified_at ON group_wiki_repository_registry USING btree (verified_at);

CREATE INDEX index_import_export_upload_upload_registry_on_retry_at ON import_export_upload_upload_registry USING btree (retry_at);

CREATE INDEX index_import_export_upload_upload_registry_on_state ON import_export_upload_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_issuable_metric_image_upload_registry_on_imi_upload_id ON issuable_metric_image_upload_registry USING btree (issuable_metric_image_upload_id);

CREATE INDEX index_issuable_metric_image_upload_registry_on_retry_at ON issuable_metric_image_upload_registry USING btree (retry_at);

CREATE INDEX index_issuable_metric_image_upload_registry_on_state ON issuable_metric_image_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_job_artifact_registry_on_artifact_id_unique ON job_artifact_registry USING btree (artifact_id);

CREATE INDEX index_job_artifact_registry_on_last_synced_at ON job_artifact_registry USING btree (last_synced_at);

CREATE INDEX index_job_artifact_registry_on_retry_at ON job_artifact_registry USING btree (retry_at);

CREATE INDEX index_job_artifact_registry_on_verified_at ON job_artifact_registry USING btree (verified_at);

CREATE INDEX index_job_artifact_registry_state ON job_artifact_registry USING btree (state);

CREATE INDEX index_lfs_object_registry_on_last_synced_at ON lfs_object_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_lfs_object_registry_on_lfs_object_id ON lfs_object_registry USING btree (lfs_object_id);

CREATE INDEX index_lfs_object_registry_on_retry_at ON lfs_object_registry USING btree (retry_at);

CREATE INDEX index_lfs_object_registry_on_success ON lfs_object_registry USING btree (success);

CREATE INDEX index_lfs_object_registry_on_verified_at ON lfs_object_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_manifest_registry_on_manifest_id ON dependency_proxy_manifest_registry USING btree (dependency_proxy_manifest_id);

CREATE INDEX index_merge_request_diff_registry_on_last_synced_at ON merge_request_diff_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_merge_request_diff_registry_on_mr_diff_id ON merge_request_diff_registry USING btree (merge_request_diff_id);

CREATE INDEX index_merge_request_diff_registry_on_retry_at ON merge_request_diff_registry USING btree (retry_at);

CREATE INDEX index_merge_request_diff_registry_on_state ON merge_request_diff_registry USING btree (state);

CREATE INDEX index_merge_request_diff_registry_on_verified_at ON merge_request_diff_registry USING btree (verified_at);

CREATE INDEX index_organization_detail_upload_registry_on_retry_at ON organization_detail_upload_registry USING btree (retry_at);

CREATE INDEX index_organization_detail_upload_registry_on_state ON organization_detail_upload_registry USING btree (state);

CREATE INDEX index_package_file_registry_on_last_synced_at ON package_file_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_package_file_registry_on_package_file_id_unique ON package_file_registry USING btree (package_file_id);

CREATE INDEX index_package_file_registry_on_retry_at ON package_file_registry USING btree (retry_at);

CREATE INDEX index_package_file_registry_on_state ON package_file_registry USING btree (state);

CREATE INDEX index_package_file_registry_on_verified_at ON package_file_registry USING btree (verified_at);

CREATE INDEX index_packages_helm_metadata_cache_registry_on_retry_at ON packages_helm_metadata_cache_registry USING btree (retry_at);

CREATE INDEX index_packages_helm_metadata_cache_registry_on_state ON packages_helm_metadata_cache_registry USING btree (state);

CREATE INDEX index_packages_nuget_symbol_registry_on_retry_at ON packages_nuget_symbol_registry USING btree (retry_at);

CREATE INDEX index_packages_nuget_symbol_registry_on_state ON packages_nuget_symbol_registry USING btree (state);

CREATE INDEX index_pages_deployment_registry_on_last_synced_at ON pages_deployment_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_pages_deployment_registry_on_pages_deployment_id ON pages_deployment_registry USING btree (pages_deployment_id);

CREATE INDEX index_pages_deployment_registry_on_retry_at ON pages_deployment_registry USING btree (retry_at);

CREATE INDEX index_pages_deployment_registry_on_state ON pages_deployment_registry USING btree (state);

CREATE INDEX index_pages_deployment_registry_on_verified_at ON pages_deployment_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_personal_snippet_upload_registry_on_ps_upload_id ON personal_snippet_upload_registry USING btree (personal_snippet_upload_id);

CREATE INDEX index_personal_snippet_upload_registry_on_retry_at ON personal_snippet_upload_registry USING btree (retry_at);

CREATE INDEX index_personal_snippet_upload_registry_on_state ON personal_snippet_upload_registry USING btree (state);

CREATE INDEX index_pipeline_artifact_registry_on_last_synced_at ON pipeline_artifact_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_pipeline_artifact_registry_on_pipeline_artifact_id ON pipeline_artifact_registry USING btree (pipeline_artifact_id);

CREATE INDEX index_pipeline_artifact_registry_on_retry_at ON pipeline_artifact_registry USING btree (retry_at);

CREATE INDEX index_pipeline_artifact_registry_on_state ON pipeline_artifact_registry USING btree (state);

CREATE INDEX index_pipeline_artifact_registry_on_verified_at ON pipeline_artifact_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_pkg_deb_proj_comp_file_registry_on_fk ON packages_debian_project_component_file_registry USING btree (packages_debian_project_component_file_id);

CREATE INDEX index_pkg_deb_proj_comp_file_registry_on_retry_at ON packages_debian_project_component_file_registry USING btree (retry_at);

CREATE INDEX index_pkg_deb_proj_comp_file_registry_on_state ON packages_debian_project_component_file_registry USING btree (state);

CREATE UNIQUE INDEX index_pkgs_nuget_symbol_registry_on_pkgs_nuget_symbol_id ON packages_nuget_symbol_registry USING btree (packages_nuget_symbol_id);

CREATE INDEX index_project_repository_registry_checksum_mismatch ON project_repository_registry USING btree (verification_retry_at) WHERE (checksum_mismatch = true);

CREATE INDEX index_project_repository_registry_on_last_synced_at ON project_repository_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_project_repository_registry_on_project_id ON project_repository_registry USING btree (project_id);

CREATE INDEX index_project_repository_registry_on_project_repository_id ON project_repository_registry USING btree (project_repository_id);

CREATE INDEX index_project_repository_registry_on_retry_at ON project_repository_registry USING btree (retry_at);

CREATE INDEX index_project_repository_registry_on_state ON project_repository_registry USING btree (state);

CREATE INDEX index_project_repository_registry_on_verified_at ON project_repository_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_project_topic_upload_registry_on_project_topic_upload_id ON project_topic_upload_registry USING btree (project_topic_upload_id);

CREATE INDEX index_project_topic_upload_registry_on_retry_at ON project_topic_upload_registry USING btree (retry_at);

CREATE INDEX index_project_topic_upload_registry_on_state ON project_topic_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_project_upload_registry_on_project_upload_id ON project_upload_registry USING btree (project_upload_id);

CREATE INDEX index_project_upload_registry_on_retry_at ON project_upload_registry USING btree (retry_at);

CREATE INDEX index_project_upload_registry_on_state ON project_upload_registry USING btree (state);

CREATE INDEX index_project_wiki_repository_registry_checksum_mismatch ON project_wiki_repository_registry USING btree (verification_retry_at) WHERE (checksum_mismatch = true);

CREATE INDEX index_project_wiki_repository_registry_on_last_synced_at ON project_wiki_repository_registry USING btree (last_synced_at);

CREATE UNIQUE INDEX index_project_wiki_repository_registry_on_project_id ON project_wiki_repository_registry USING btree (project_id);

CREATE INDEX index_project_wiki_repository_registry_on_retry_at ON project_wiki_repository_registry USING btree (retry_at);

CREATE INDEX index_project_wiki_repository_registry_on_state ON project_wiki_repository_registry USING btree (state);

CREATE INDEX index_project_wiki_repository_registry_on_verified_at ON project_wiki_repository_registry USING btree (verified_at);

CREATE INDEX index_snippet_repository_registry_checksum_mismatch ON snippet_repository_registry USING btree (verification_retry_at) WHERE (checksum_mismatch = true);

CREATE INDEX index_snippet_repository_registry_on_last_synced_at ON snippet_repository_registry USING btree (last_synced_at);

CREATE INDEX index_snippet_repository_registry_on_retry_at ON snippet_repository_registry USING btree (retry_at);

CREATE UNIQUE INDEX index_snippet_repository_registry_on_snippet_repository_id ON snippet_repository_registry USING btree (snippet_repository_id);

CREATE INDEX index_snippet_repository_registry_on_state ON snippet_repository_registry USING btree (state);

CREATE INDEX index_snippet_repository_registry_on_verified_at ON snippet_repository_registry USING btree (verified_at);

CREATE INDEX index_state_in_lfs_objects ON lfs_object_registry USING btree (state);

CREATE UNIQUE INDEX index_supply_chain_attestation_registry_on_attestation_id ON supply_chain_attestation_registry USING btree (supply_chain_attestation_id);

CREATE INDEX index_supply_chain_attestation_registry_on_retry_at ON supply_chain_attestation_registry USING btree (retry_at);

CREATE INDEX index_supply_chain_attestation_registry_on_state ON supply_chain_attestation_registry USING btree (state);

CREATE INDEX index_terraform_state_version_registry_on_last_synced_at ON terraform_state_version_registry USING btree (last_synced_at);

CREATE INDEX index_terraform_state_version_registry_on_retry_at ON terraform_state_version_registry USING btree (retry_at);

CREATE INDEX index_terraform_state_version_registry_on_state ON terraform_state_version_registry USING btree (state);

CREATE UNIQUE INDEX index_terraform_state_version_registry_on_t_state_version_id ON terraform_state_version_registry USING btree (terraform_state_version_id);

CREATE INDEX index_terraform_state_version_registry_on_verified_at ON terraform_state_version_registry USING btree (verified_at);

CREATE UNIQUE INDEX index_tf_state_versions_registry_tf_state_versions_id_unique ON terraform_state_version_registry USING btree (terraform_state_version_id);

CREATE INDEX index_user_upload_registry_on_retry_at ON user_upload_registry USING btree (retry_at);

CREATE INDEX index_user_upload_registry_on_state ON user_upload_registry USING btree (state);

CREATE UNIQUE INDEX index_user_upload_registry_on_user_upload_id ON user_upload_registry USING btree (user_upload_id);

CREATE UNIQUE INDEX index_vuln_remediation_upload_registry_on_upload_id ON vulnerability_remediation_upload_registry USING btree (vulnerability_remediation_upload_id);

CREATE INDEX index_vulnerability_archive_export_upload_registry_on_retry_at ON vulnerability_archive_export_upload_registry USING btree (retry_at);

CREATE INDEX index_vulnerability_archive_export_upload_registry_on_state ON vulnerability_archive_export_upload_registry USING btree (state);

CREATE INDEX index_vulnerability_export_part_upload_registry_on_retry_at ON vulnerability_export_part_upload_registry USING btree (retry_at);

CREATE INDEX index_vulnerability_export_part_upload_registry_on_state ON vulnerability_export_part_upload_registry USING btree (state);

CREATE INDEX index_vulnerability_export_upload_registry_on_retry_at ON vulnerability_export_upload_registry USING btree (retry_at);

CREATE INDEX index_vulnerability_export_upload_registry_on_state ON vulnerability_export_upload_registry USING btree (state);

CREATE INDEX index_vulnerability_remediation_upload_registry_on_retry_at ON vulnerability_remediation_upload_registry USING btree (retry_at);

CREATE INDEX index_vulnerability_remediation_upload_registry_on_state ON vulnerability_remediation_upload_registry USING btree (state);

CREATE INDEX issuable_metric_image_upload_registry_failed_verification ON issuable_metric_image_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX issuable_metric_image_upload_registry_needs_verification ON issuable_metric_image_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX issuable_metric_image_upload_registry_pending_verification ON issuable_metric_image_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX job_artifact_registry_failed_verification ON job_artifact_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX job_artifact_registry_needs_verification ON job_artifact_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX job_artifact_registry_pending_verification ON job_artifact_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX lfs_object_registry_failed_verification ON lfs_object_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX lfs_object_registry_needs_verification ON lfs_object_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX lfs_object_registry_pending_verification ON lfs_object_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX merge_request_diff_registry_failed_verification ON merge_request_diff_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX merge_request_diff_registry_needs_verification ON merge_request_diff_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX merge_request_diff_registry_pending_verification ON merge_request_diff_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX package_file_registry_failed_verification ON package_file_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX package_file_registry_needs_verification ON package_file_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX package_file_registry_pending_verification ON package_file_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX packages_helm_metadata_cache_registry_failed_verification ON packages_helm_metadata_cache_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX packages_helm_metadata_cache_registry_needs_verification ON packages_helm_metadata_cache_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX packages_helm_metadata_cache_registry_pending_verification ON packages_helm_metadata_cache_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX packages_nuget_symbol_registry_failed_verification ON packages_nuget_symbol_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX packages_nuget_symbol_registry_needs_verification ON packages_nuget_symbol_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX packages_nuget_symbol_registry_pending_verification ON packages_nuget_symbol_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX pages_deployment_registry_failed_verification ON pages_deployment_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX pages_deployment_registry_needs_verification ON pages_deployment_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX pages_deployment_registry_pending_verification ON pages_deployment_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX personal_snippet_upload_registry_failed_verification ON personal_snippet_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX personal_snippet_upload_registry_needs_verification ON personal_snippet_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX personal_snippet_upload_registry_pending_verification ON personal_snippet_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX piere_export_upload_upload_registry_failed_verification ON project_import_export_relation_export_upload_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX piere_export_upload_upload_registry_retried_at ON project_import_export_relation_export_upload_upload_registry USING btree (retry_at);

CREATE INDEX piere_export_upload_upload_state ON project_import_export_relation_export_upload_upload_registry USING btree (state);

CREATE INDEX piere_upload_upload_registry_needs_verification ON project_import_export_relation_export_upload_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX piere_upload_upload_registry_pending_verification ON project_import_export_relation_export_upload_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX pipeline_artifact_registry_failed_verification ON pipeline_artifact_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX pipeline_artifact_registry_needs_verification ON pipeline_artifact_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX pipeline_artifact_registry_pending_verification ON pipeline_artifact_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX pkg_deb_proj_comp_file_registry_failed_verification ON packages_debian_project_component_file_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX pkg_deb_proj_comp_file_registry_needs_verification ON packages_debian_project_component_file_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX pkg_deb_proj_comp_file_registry_pending_verification ON packages_debian_project_component_file_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX project_repository_registry_failed_verification ON project_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX project_repository_registry_needs_verification ON project_repository_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX project_repository_registry_pending_verification ON project_repository_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX project_topic_upload_registry_failed_verification ON project_topic_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX project_topic_upload_registry_needs_verification ON project_topic_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX project_topic_upload_registry_pending_verification ON project_topic_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX project_upload_registry_failed_verification ON project_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX project_upload_registry_needs_verification ON project_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX project_upload_registry_pending_verification ON project_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX project_wiki_repository_registry_failed_verification ON project_wiki_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX project_wiki_repository_registry_needs_verification ON project_wiki_repository_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX project_wiki_repository_registry_pending_verification ON project_wiki_repository_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX snippet_repository_registry_failed_verification ON snippet_repository_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX snippet_repository_registry_needs_verification ON snippet_repository_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX snippet_repository_registry_pending_verification ON snippet_repository_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX supply_chain_attestation_registry_failed_verification ON supply_chain_attestation_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX supply_chain_attestation_registry_needs_verification ON supply_chain_attestation_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX supply_chain_attestation_registry_pending_verification ON supply_chain_attestation_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX terraform_state_version_registry_failed_verification ON terraform_state_version_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX terraform_state_version_registry_needs_verification ON terraform_state_version_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX terraform_state_version_registry_pending_verification ON terraform_state_version_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX user_upload_registry_failed_verification ON user_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX user_upload_registry_needs_verification ON user_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX user_upload_registry_pending_verification ON user_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));

CREATE INDEX vulnerability_remediation_upload_registry_failed_verification ON vulnerability_remediation_upload_registry USING btree (verification_retry_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 3));

CREATE INDEX vulnerability_remediation_upload_registry_needs_verification ON vulnerability_remediation_upload_registry USING btree (verification_state) WHERE ((state = 2) AND (verification_state = ANY (ARRAY[0, 3])));

CREATE INDEX vulnerability_remediation_upload_registry_pending_verification ON vulnerability_remediation_upload_registry USING btree (verified_at NULLS FIRST) WHERE ((state = 2) AND (verification_state = 0));
