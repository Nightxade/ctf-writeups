### Execute local server
`bundle exec jekyll serve`

### Ruby gem 'webrick' required for local server
https://github.com/jekyll/jekyll/issues/8523#issuecomment-751409319

### Keep sorting of CTF challs in order
same date, all start with same case. date format: YYYY-MM-DD

### Github assets file links
Make sure to have `/ctf-writeups/blob/master/assets`

### Latex Support
Put this in Markdown files:
<script
  src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML"
  type="text/javascript">
</script>
See [https://www.fabriziomusacchio.com/blog/2021-08-10-How_to_use_LaTeX_in_Markdown/](https://www.fabriziomusacchio.com/blog/2021-08-10-How_to_use_LaTeX_in_Markdown/) for more info

### index.md not showing up correctly
Make sure the title includes spaces between all words and the category and tags do not.  

### Embed image
<img src="[imgur link]" alt="[description]" style="display: block; margin-left: auto; margin-right: auto; width: 100%;"/>  

### Google Site Verification
Add "google1f873ae9edd1f806.html" to /_pages with content "google-site-verification: google1f873ae9edd1f806.html"