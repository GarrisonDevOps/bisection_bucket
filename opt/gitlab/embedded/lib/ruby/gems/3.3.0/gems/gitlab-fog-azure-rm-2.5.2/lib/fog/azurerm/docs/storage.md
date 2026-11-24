# Storage

This document explains how to get started using Azure Storage Service with Fog. With this gem you can create, update, list or delete storage accounts.

## Usage

First of all, you need to require the Fog library by executing:

```ruby
require 'fog/azurerm'
```

## Create Connection

If you only want to manage the storage data, you can create the connection without the Azure subscription information:

```ruby
fog_storage_service = Fog::AzureRM::Storage.new(
  azure_storage_account_name:   '<Storage Account Name>',                                             # Name of an Azure Storage Account
  azure_storage_access_key:     '<Storage Account Key>',                                              # Key of an Azure Storage Account
  environment:                  '<AzureCloud/AzureChinaCloud/AzureUSGovernment/AzureGermanCloud>'     # Azure cloud environment. Default is AzureCloud.
)
```

## Check Storage Container Existence

```ruby
fog_storage_service.directories.check_container_exists('<Container Name>')
```

## Create a storage container

Create a storage container in the current storage account.

```ruby
directory = fog_storage_service.directories.create(
   key: '<Container Name>',
   public: <True/False>
)
puts directory.key
```

## List storage containers

List all the storage containers in the current storage accounts.

```ruby
fog_storage_service.directories.each do |directory|
  puts directory.key
end
```

## Get the access control level of the storage container

Get the permissions for the specified container. The permissions indicate whether container data may be accessed publicly.

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
puts directory.acl
```

## Set the access control level of the storage container

Set the permissions for the specified container. The permissions indicate whether container data may be accessed publicly. The container permissions provide the following options for managing container access:

  - ###### Container

    Full public read access. Container and blob data can be read via anonymous request. Clients can enumerate blobs within the container via anonymous request, but cannot enumerate containers within the storage account.

  - ###### Blob

    Public read access for blobs only. Blob data within this container can be read via anonymous request, but container data is not available. Clients cannot enumerate blobs within the container via anonymous request.

  - ###### Nil

    No public read access. Container and blob data can be read by the account owner only.

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
directory.acl = '<Container Name>'
directory.save(is_create: <True/False>)
```

## Delete the storage container

Mark the specified container for deletion. The container and any blobs contained within it are later deleted during garbage collection.

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
puts directory.destroy
```

## Upload data as a block blob
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
options = {
  key: '<Blob Name>',
  body: '<Blob Content>'
}
new_block_blob = directory.files.create(options)
puts new_block_blob.inspect
```

## Upload a local file as a block blob
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
File.open('<File Path>') do |file|
  options = {
    key: '<Blob Name>',
    body: file
  }
  new_block_blob = directory.files.create(options)
  puts new_block_blob.inspect
end
```

## Upload VHD data as a page blob
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
options = {
  key: '<Blob Name>',
  body: '<Blob Content>',
  blob_type: '<Blob Type>'
}
new_page_blob = directory.files.create(options)
puts new_page_blob.inspect
```

## Upload a local VHD as a page blob
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
File.open('<File Path>') do |file|
  options = {
    key: '<Blob Name>',
    body: file,
    blob_type: '<Blob Type>'
  }
  new_page_blob = directory.files.create(options)
  puts new_page_blob.inspect
end
```

## Copy Blob from one container to another
```ruby
directory = fog_storage_service.directories.get('<Source Container Name>', max_keys: <Maximum No. of Keys Value>)
copied_blob = directory.files.head('<Source Blob Name>').copy('<Destination Container Name>', '<Destination Blob Name>')
puts copied_blob.inspect
```

## Copy Blob from one uri to self
```ruby
directory = fog_storage_service.directories.get('<Destination Container Name>', max_keys: <Maximum No. of Keys Value>)
copied_blob = directory.files.new(key: '<Destination Blob Name>')
copied_blob.copy_from_uri('<Source Blob Uri>')
puts copied_blob.inspect
```

## Download a small blob to a local file
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
blob = directory.files.get('<Blob Name>')
File.open('<File Path>', 'wb') do |file|
  file.write(blob.body)
end
puts "File Size: #{::File.size <File Path>}"
```

## Download a large blob to a local file
```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
File.open('<File Path>', 'wb') do |file|
  directory.files.get('<Blob Name>') do |chunk, remaining_bytes, total_bytes|
    puts "remaining_bytes: #{remaining_bytes}, total_bytes: #{total_bytes}"
    file.write(chunk)
  end
end
puts "File Size: #{::File.size <File Path>}"
```

## Delete the storage blob

Mark the specified blob for deletion. The blob is later deleted during garbage collection.

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
blob = directory.files.head('<Blob Name>')
puts blob.destroy
```

## Set storage blob properties

Set the storage blob properties.

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
blob = directory.files.head('<Blob Name>')
blob.content_language = '<Language>'
blob.content_disposition = '<Content Disposition Type>'
blob.save(update_body: <True/False>)
```

## Metadata

Metadata allows us to provide descriptive information about specific containers or blobs. This is simply providing name/value pairs of data we want to set on the container or blob.

### Get Blob Metadata

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
blob = directory.files.head('<Blob Name>')
puts blob.metadata
```

### Set Blob Metadata

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
blob = directory.files.head('<Blob Name>')
blob.metadata = {
  Category: '<Category Value>',
  Resolution: '<Resolution Value>'
}
blob.save(update_body: <True/False>)
```

### Get Container Metadata

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
puts directory.metadata
```

### Set Container Metadata

```ruby
directory = fog_storage_service.directories.get('<Container Name>', max_keys: <Maximum No. of Keys Value>)
directory.metadata = {
  CreatedBy: '<Username>',
  SourceMachine: '<Machine Name>',
  category: '<Category Value>',
  docType: '<Document Type>'
}
directory.save(is_create: <True/False>)
```

## Support and Feedback
Your feedback is appreciated! If you have specific issues with the fog ARM, you should file an issue via Github.




