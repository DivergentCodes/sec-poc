# pkg-d-macos-chrome

This package executes a postinstall script for the `@divergentcodes/pkg-d-macos-chrome` package. It modifies the Chrome preferences file to grant microphone and camera access to the `https://divergent.codes:443` origin.

The script is only supported for Chrome on MacOS.

## Usage

```bash
npm install @divergentcodes/pkg-d-macos-chrome
```

## How it works

The `postinstall.js` script is executed after the package is installed. It modifies the Chrome preferences file to grant microphone and camera access to the `https://divergent.codes:443` origin.

The Chrome preferences file is located at `$HOME/Library/Application Support/Google/Chrome/Default/Preferences`.

The script reads the Chrome preferences file, modifies the `media_stream_mic` and `media_stream_camera` settings to grant access to the `https://divergent.codes:443` origin, and writes the modified preferences back to the file.

The JSON paths modified are:

```json
"profile.content_settings.exceptions.media_stream_mic"
"profile.content_settings.exceptions.media_stream_camera"
```

To view the relevant parts of the preferences file with `jq`:

```bash
npm run show:mic
npm run show:cam
```

Chrome pages to see the current settings:
- [chrome://settings/content/microphone](chrome://settings/content/microphone)
- [chrome://settings/content/camera](chrome://settings/content/camera)
- [chrome://settings/content](chrome://settings/content)


## Resources

- [yo-yo-yo-jbo/hm-surf](https://github.com/yo-yo-yo-jbo/hm-surf)