import axios from "axios";
import { XMLParser } from "fast-xml-parser";

export const getLatestExploits = async (req, res) => {
  try {
    const response = await axios.get("https://www.exploit-db.com/rss.xml", {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
      },
      timeout: 10000
    });

    const parser = new XMLParser();
    const jObj = parser.parse(response.data);
    const items = jObj.rss.channel.item || [];

    const exploits = (Array.isArray(items) ? items : [items]).slice(0, 20).map(item => ({
      title: item.title,
      link: item.link,
      description: item.description,
      pubDate: item.pubDate
    }));

    return res.json({ success: true, exploits });
  } catch (error) {
    console.error("[Exploit-DB Feed Error]:", error.message);
    return res.status(500).json({ success: false, error: "Error connecting to Exploit-DB feed. Please try again later." });
  }
};
