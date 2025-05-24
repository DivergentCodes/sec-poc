# Browser Permissions

## Permissions

### Microphone

### Camera


## Paths & Files

### MacOS Chrome Preferences

On MacOS, Chrome permissions granted to origins can be viewed in the
preferences JSON file: `$HOME/Library/Application Support/Google/Chrome/Default/Preferences`

```bash
# Overwrite the Chrome preferences file with the modified JSON
jq -c '.' Preferences.json > "$HOME/Library/Application Support/Google/Chrome/Default/Preferences"
```

The granted permissions are under the key `profile.content_settings.exceptions`.
