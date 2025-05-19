def raw_config_parse(config_filename, parse_subsections=True):
    """Returns the parsed INI config contents.

    Each section name is a top level key.

    :param config_filename: The name of the INI file to parse

    :param parse_subsections: If True, parse indented blocks as
       subsections that represent their own configuration dictionary.
       For example, if the config file had the contents::

           s3 =
              signature_version = s3v4
              addressing_style = path

        The resulting ``raw_config_parse`` would be::

            {'s3': {'signature_version': 's3v4', 'addressing_style': 'path'}}

       If False, do not try to parse subsections and return the indented
       block as its literal value::

            {'s3': '\nsignature_version = s3v4\naddressing_style = path'}

    :returns: A dict with keys for each profile found in the config
        file and the value of each key being a dict containing name
        value pairs found in that profile.

    :raises: ConfigNotFound, ConfigParseError
    """
    config = {}
    path = config_filename
    if path is not None:
        path = os.path.expandvars(path)
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise botocore.exceptions.ConfigNotFound(path=_unicode_path(path))
        cp = configparser.RawConfigParser()
        try:
            cp.read([path])
        except (configparser.Error, UnicodeDecodeError) as e:
            raise botocore.exceptions.ConfigParseError(
                path=_unicode_path(path), error=e
            ) from None
        else:
            for section in cp.sections():
                config[section] = {}
                for option in cp.options(section):
                    config_value = cp.get(section, option)
                    if parse_subsections and config_value.startswith('\n'):
                        # Then we need to parse the inner contents as
                        # hierarchical.  We support a single level
                        # of nesting for now.
                        try:
                            config_value = _parse_nested(config_value)
                        except ValueError as e:
                            raise botocore.exceptions.ConfigParseError(
                                path=_unicode_path(path), error=e
                            ) from None
                    config[section][option] = config_value
    return config


def _unicode_path(path):
    if isinstance(path, str):
        return path
    # According to the documentation getfilesystemencoding can return None
    # on unix in which case the default encoding is used instead.
    filesystem_encoding = sys.getfilesystemencoding()
    if filesystem_encoding is None:
        filesystem_encoding = sys.getdefaultencoding()
    return path.decode(filesystem_encoding, 'replace')


def _parse_nested(config_value):
    # Given a value like this:
    # \n
    # foo = bar
    # bar = baz
    # We need to parse this into
    # {'foo': 'bar', 'bar': 'baz}
    parsed = {}
    for line in config_value.splitlines():
        line = line.strip()
        if not line:
            continue
        # The caller will catch ValueError
        # and raise an appropriate error
        # if this fails.
        key, value = line.split('=', 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_section(key, values):
    result = {}
    try:
        parts = shlex.split(key)
    except ValueError:
        return result
    if len(parts) == 2:
        result[parts[1]] = values
    return result


def build_profile_map(parsed_ini_config):
    """Convert the parsed INI config into a profile map.

    The config file format requires that every profile except the
    default to be prepended with "profile", e.g.::

        [profile test]
        aws_... = foo
        aws_... = bar

        [profile bar]
        aws_... = foo
        aws_... = bar

        # This is *not* a profile
        [preview]
        otherstuff = 1

        # Neither is this
        [foobar]
        morestuff = 2

    The build_profile_map will take a parsed INI config file where each top
    level key represents a section name, and convert into a format where all
    the profiles are under a single top level "profiles" key, and each key in
    the sub dictionary is a profile name.  For example, the above config file
    would be converted from::

        {"profile test": {"aws_...": "foo", "aws...": "bar"},
         "profile bar": {"aws...": "foo", "aws...": "bar"},
         "preview": {"otherstuff": ...},
         "foobar": {"morestuff": ...},
         }

    into::

        {"profiles": {"test": {"aws_...": "foo", "aws...": "bar"},
                      "bar": {"aws...": "foo", "aws...": "bar"},
         "preview": {"otherstuff": ...},
         "foobar": {"morestuff": ...},
        }

    If there are no profiles in the provided parsed INI contents, then
    an empty dict will be the value associated with the ``profiles`` key.

    .. note::

        This will not mutate the passed in parsed_ini_config.  Instead it will
        make a deepcopy and return that value.

    """
    parsed_config = copy.deepcopy(parsed_ini_config)
    profiles = {}
    sso_sessions = {}
    services = {}
    final_config = {}
    for key, values in parsed_config.items():
        if key.startswith("profile"):
            profiles.update(_parse_section(key, values))
        elif key.startswith("sso-session"):
            sso_sessions.update(_parse_section(key, values))
        elif key.startswith("services"):
            services.update(_parse_section(key, values))
        elif key == 'default':
            # default section is special and is considered a profile
            # name but we don't require you use 'profile "default"'
            # as a section.
            profiles[key] = values
        else:
            final_config[key] = values
    final_config['profiles'] = profiles
    final_config['sso_sessions'] = sso_sessions
    final_config['services'] = services
    return final_config
