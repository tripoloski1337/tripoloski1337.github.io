---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: home
---

<header>
      <h1>{{ site.title | default: site.github.repository_name }}</h1>
      <h2>{{ site.description | default: site.github.project_tagline }}</h2>
    </header>
{% for post in site.posts %}   
    <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
    <p><small><strong>{{ post.date | date: "%B %e, %Y" }}</strong> . {{ post.category }} . <a href="http://tripoloski1337.github.io{{ post.url }}#disqus_thread"></a></small></p>            
{% endfor %}
