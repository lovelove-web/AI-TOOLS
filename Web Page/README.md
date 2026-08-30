# AegisForge Security — landing page

Responsive company site for a cybersecurity consulting firm. Built with HTML5, CSS3, JavaScript, and Bootstrap 5 (CDN). No build step.

## Run locally

1. Open a terminal in this folder.
2. Start a static server (pick one):

```bash
# Python 3
python3 -m http.server 8080
```

```bash
# Node (if you have npx)
npx --yes serve -l 8080
```

3. In a browser, open [http://localhost:8080](http://localhost:8080).

You can also open `index.html` directly from the file system. A local server is preferred so Bootstrap and icons load reliably if you later add modules or relative assets.

## Site map

| Page | Path |
| --- | --- |
| Home | `index.html` |
| About Us | `about.html` |
| Services | `services.html` |
| Service details | `services/*.html` (6 practices) |
| Products | `products.html` |
| Testimonials | `testimonials.html` |
| Contact Us | `contact.html` |

## Files

| File | Role |
| --- | --- |
| `index.html` | Home page with SOC hero image |
| `about.html` / `services.html` / `products.html` / `testimonials.html` / `contact.html` | Section pages |
| `services/*.html` | Detailed service briefs |
| `assets/soc-operations.jpg` | Hero image |
| `css/styles.css` | Theme, layout, animations |
| `js/main.js` | Active nav, form validation, reveal-on-scroll |
