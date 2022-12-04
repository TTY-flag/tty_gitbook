// book.js
module.exports = {
    title: 'Gitbook电子书',
    author: 'TTY',
    lang: 'zh-cn',
    description: 'Gitbook电子书示例项目',
    plugins: [
        "-sharing",
        "sharing-plus",
        "-search",
        "search-pro",
        "code",
        "expandable-chapters",
    ],
    pluginsConfig: {
        "sharing": {
            "douban": false,
            "facebook": false,
            "google": false,
            "hatenaBookmark": false,
            "instapaper": false,
            "line": false,
            "linkedin": false,
            "messenger": false,
            "pocket": false,
            "qq": false,
            "qzone": false,
            "stumbleupon": false,
            "twitter": false,
            "viber": false,
            "vk": false,
            "weibo": false,
            "whatsapp": false,
            "all": [
                "facebook", "google", "twitter",
                "weibo", "qq", "linkedin",
                "qzone", "douban"
            ]
        },
        "code": {
            "copyButtons": true
        }
    }
};