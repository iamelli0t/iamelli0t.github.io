# My study of vulnerability and exploit

Blog built with [Hugo](https://gohugo.io/) and the [PaperMod](https://github.com/adityatelange/hugo-PaperMod) theme, vendored under `themes/hugo-PaperMod/` at master commit `d376885` (the revision that supports Hugo 0.146+'s new template system; to upgrade, copy the upstream theme over that directory).

Pushing to `main` triggers a GitHub Actions build and deploy.

## Local preview

```sh
brew install hugo
./scripts/server   # http://localhost:1313/
```

## Writing a post

Create a markdown file under `content/posts/` — either `YYYY-MM-DD-slug.md` or any name with a `date:` in the front matter — and copy the front matter of an existing post. Images go in `static/images/<post-name>/` and are referenced from the body as `/images/<post-name>/x.png`.

## History

- 2021-03 to 2021-08: Jekyll with the Hamilton theme (rollback anchor: git tag `jekyll-final`)
- 2026-09: migrated to Hugo + PaperMod; deployment moved from GitHub Pages' native Jekyll build to GitHub Actions