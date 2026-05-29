export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET');

  const sources = [
    { url: 'https://www.hrdive.com/feeds/news', name: 'HR Dive' },
    { url: 'https://hrexecutive.com/feed', name: 'HR Executive' },
    { url: 'https://www.hrnewsfeed.com/feed', name: 'HR News Feed' }
  ];

  try {
    const results = await Promise.allSettled(
      sources.map(async (source) => {
        const response = await fetch(source.url);
        const xml = await response.text();
        const items = [];
        const itemMatches = xml.matchAll(/<item>([\s\S]*?)<\/item>/g);
        for (const match of itemMatches) {
          const content = match[1];
          const title = (content.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/) || content.match(/<title>(.*?)<\/title>/) || [])[1] || '';
          const link = (content.match(/<link>(.*?)<\/link>/) || [])[1] || '';
          const pubDate = (content.match(/<pubDate>(.*?)<\/pubDate>/) || [])[1] || '';
          if (title) items.push({ title: title.replace(/<!\[CDATA\[|\]\]>/g, '').trim(), link: link.trim(), pubDate, source: source.name });
        }
        return items.slice(0, 5);
      })
    );

    const allItems = results
      .filter(r => r.status === 'fulfilled')
      .flatMap(r => r.value)
      .sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate))
      .slice(0, 8);

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(allItems);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch news feeds' });
  }
}
