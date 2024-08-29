# Format Report

Hi 🖖 Some files are not correctly formatted.
You can follow these steps to solve the issue:

1. Download the git diff from this URL (you can find it at the bottom of the page, it's called `{{ .file }}`):
    {{ .url }}

2. Unzip it, you can use the `unzip` tool for example:

```bash
    unzip {{ .file }}.zip
```

3. Apply it with:

```bash
    git apply {{ .file }}
```

4. Add a **NEW** commit to your pull request with the title:

```bash
    style: apply format
```
