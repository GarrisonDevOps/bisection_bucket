# User Experience SLIs

This module covers the definition for User Experience SLIs, as described in the [blueprint](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/user_experience_slis/#user-experience-sli-definition).

## Configuration

### Logger Configuration

By default, `Labkit::UserExperienceSli` uses `Labkit::Logging::JsonLogger.new($stdout)` for logging. You can configure a custom logger:

```ruby
Labkit::UserExperienceSli.configure do |config|
  config.logger = Labkit::Logging::JsonLogger.new($stdout)
end
```

This configuration affects all User Experience SLI instances and their logging output.

### Registry Path Configuration

By default, user experience SLI definitions are loaded from the `config/user_experience_slis` directory. You can configure a custom registry path:

```ruby
Labkit::UserExperienceSli.configure do |config|
  config.registry_path = "my/custom/path"
end
```

This allows you to:
- Store user experience SLI definitions in a different directory structure
- Use different paths for different environments
- Organize definitions according to your application's needs

**Note:** The registry is automatically reset when the configuration changes, so the new path takes effect immediately.

### RefResolver Timeout Configuration

When validating user experience SLI definitions against JSON schemas, the system may need to fetch remote schema references over HTTP/HTTPS. By default, the timeout for these requests is 2 seconds. You can configure a custom timeout:

```ruby
Labkit::UserExperienceSli.configure do |config|
  config.ref_resolver_timeout = 5  # Set timeout to 5 seconds
end
```

This configuration is useful when:
- Working in environments with slower network connections
- Fetching schemas from remote servers with higher latency
- Needing stricter timeout constraints for faster failure detection

**Note:** The timeout applies to both connection opening and reading operations when fetching remote JSON schema references.

### Feature Category Schema Preloading

When validating user experience SLI definitions, the system validates the `feature_category` field against a remote up to date JSON schema (cached after first request) by default. To avoid HTTP requests at runtime, you can preload the feature category schema from a local file:

```ruby
Labkit::UserExperienceSli.configure do |config|
  config.feature_category_schema_path = Rails.root.join('config/feature_categories/schema.json').to_s
end
```

JSON schema example:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "string",
  "enum": ["source_code_management", "team_planning", "observability"]
}
```

The current single source of truth can be found in https://gitlab.com/gitlab-org/gitlab/-/raw/master/config/feature_categories/schema.json.


This configuration is useful when:
- Running in environments without external network access
- Ensuring consistent validation against a known schema version

### User Experience Definitions

User Experience SLI definitions will be lazy loaded from the default directory (`config/user_experience_slis`).

Create a new user experience SLI file in the registry directory, e.g. config/user_experience_slis/merge_request_creation.yaml

The basename of the file will be taken as the user_experience_id.

The schema header is optional, but if you're using VSCode (or any other editor with support), you can get them validated
instantaneously in the editor via a [JSON schema plugin](https://marketplace.visualstudio.com/items?itemName=remcohaszing.schemastore).

```yaml
# yaml-language-server: $schema=https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/raw/master/config/user_experience_slis/schema.json
description: "Creating a new merge request in a project"
feature_category: "source_code_management"
urgency: "sync_fast"
```

**Feature category**

https://docs.gitlab.com/development/feature_categorization/#feature-categorization.

**Urgency**

| Threshold    | Description                                                                                                                                                      | Examples                                                                       | Value |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|-------|
| `sync_fast`  | A user is awaiting a synchronous response which needs to be returned before they can continue with their action                                                  | A full-page render                                                             | 2s    |
| `sync_slow`  | A user is awaiting a synchronous response which needs to be returned before they can continue with their action, but which the user may accept a slower response | Displaying a full-text search response while displaying an amusement animation | 5s    |
| `async_fast` | An async process which may block a user from continuing with their user journey                                                                                  | MR diff update after git push                                                  | 15s   |
| `async_slow` | An async process which will not block a user and will not be immediately noticed as being slow                                                                   | Notification following an assignment                                           | 5m    |
| `custom`     | A user experience whose acceptable duration does not match the predefined urgency buckets                                                                        | Creating a merge request with an accepted threshold of 90s                     | Set by `apdex_threshold_s` |

**Custom Apdex thresholds**

Use `urgency: "custom"` when none of the predefined thresholds accurately represents the expected user experience. Custom urgency requires `apdex_threshold_s`.

```yaml
description: "Creating a new merge request in a project"
feature_category: "code_review_workflow"
urgency: "custom"
apdex_threshold_s: 90
```

`apdex_threshold_s` is measured in seconds, must be greater than `0`, and cannot exceed `600`.

Prefer the predefined urgency values unless the SLI would otherwise be permanently red or permanently green because the predefined thresholds do not match the experience.

## Usage

The `Labkit::UserExperienceSli` module provides a simple API for measuring and tracking user experience SLIs in your application.


#### Accessing a User Experience SLI

```ruby
# Get a user experience SLI by ID
experience = Labkit::UserExperienceSli.get('merge_request_creation')
```

#### Using with a Block (Recommended)

The simplest way to use user experience SLIs is with a block, which automatically handles starting and completing the experience:

```ruby
Labkit::UserExperienceSli.start('merge_request_creation') do |experience|
  # Your code here
  create_merge_request

  # Add checkpoints for important milestones
  experience.checkpoint

  validate_merge_request
  experience.checkpoint

  send_notifications
end
```

#### Manual Control

For more control, you can manually start, checkpoint, and complete experiences:

```ruby
experience = Labkit::UserExperienceSli.get('merge_request_creation')
experience.start

# Perform some work
create_merge_request

# Mark important milestones
experience.checkpoint

# Perform more work
validate_merge_request
experience.checkpoint

# Complete the experience
experience.complete
```

#### Observing a Past Experience

When an action already happened and you want to record its duration retroactively, use `observed`. It fires the start and end metrics without registering in the active context:

```ruby
Labkit::UserExperienceSli.observed('merge_request_creation', start_time: start_time_of_past_action)
```

You can also signal that an error occurred during the action:

```ruby
Labkit::UserExperienceSli.observed('merge_request_creation', start_time: start_time_of_past_action, error: true)
```

Extra labels are forwarded to both the start and end log events:

```ruby
Labkit::UserExperienceSli.observed('merge_request_creation', start_time: start_time_of_past_action, worker: 'MyWorker')
```

#### Resuming Experiences

You can resume a user experience SLI that was previously started and stored in the context. This is useful for distributed operations or when work spans multiple processes.

Just like the start method, we can use a block to automatically complete a user experience SLI:

```ruby
# Resume an experience from context (with block)
Labkit::UserExperienceSli.resume(:merge_request_creation) do |experience|
  # Continue the work from where it left off
  finalize_merge_request

  # Add checkpoints as needed
  experience.checkpoint

  send_notifications
end
```
Or manually:

```ruby
# Resume an experience from context (manual control)
experience = Labkit::UserExperienceSli.resume(:merge_request_creation)

# Continue the work
finalize_merge_request
experience.checkpoint

# Complete the experience
experience.complete
```

**Note:** The `resume` method loads the start time from the Labkit context. If no user experience SLI data exists in the context, it behaves the same as calling methods on an unstarted experience and safely ignores the operation.

### Error Handling

When using the block form, errors are automatically captured:

```ruby
Labkit::UserExperienceSli.start('merge_request_creation') do |experience|
  # If this raises an exception, it will be captured automatically
  risky_operation
end
```

For manual control, you can mark errors explicitly:

```ruby
experience = Labkit::UserExperienceSli.get('merge_request_creation')
experience.start

begin
  risky_operation
rescue StandardError => e
  experience.error!(e)
  raise
ensure
  experience.complete
end
```

### Error Behavior

- In `development` and `test` environments, accessing a non-existent user experience SLI will raise a `NotFoundError`
- In other environments, a null object is returned that safely ignores all method calls
- Attempting to checkpoint or complete an unstarted experience will safely ignore the operation
