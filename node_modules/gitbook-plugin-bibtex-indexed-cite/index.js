var bibtexParse = require('bibtex-parser-js');
var _ = require('lodash');
var fs = require('fs');

module.exports = {
    book: {
        assets: './assets',
        css: ["style.css"]
    },

    filters: {
        cite: function(key) {
            var citation = _.find(this.config.get('bib'), {'citationKey': key.toUpperCase()});

            var path = this.config.get('pluginsConfig')['bibtex-indexed-cite'].path;            

            if (citation !== undefined) {
                
                var index = _.indexOf(this.config.get('bib'), citation) + 1;    
                                
                return '<a href="' + path + 'References.html#cite-' + index + '">[' + index + ']</a>';

            } else {
                return "[Citation not found]";
            }
        }
    },

    hooks: {
        init: function() {
            var bib = fs.readFileSync('literature.bib', 'utf8');
            this.config.set('bib', bibtexParse.toJSON(bib));
            this.config.set('bibCount', 0);                     
        }
    },

    blocks: {
        references: {
            process: function(blk) {
                var bib = this.config.get('bib');
                           
                var result = '<table class="references">';

                bib.forEach(function(item) {                

                    var index = _.indexOf(bib, item) + 1;                

                    result += '<tr><td><span class="citation-number" id="cite-' + index + '">' + index + '</span></td><td>';

                    if (item.entryTags.AUTHOR) {
                        result += formatAuthors(item.entryTags.AUTHOR) + ', ';
                    }
                    if (item.entryTags.TITLE) {
                        if (item.entryTags.URL) {
                            result += '<a href="' + item.entryTags.URL + '">' + item.entryTags.TITLE + '</a>, ';
                        } else {
                            result += item.entryTags.TITLE + ', ';
                        }
                    }
                    if (item.entryTags.BOOKTITLE) {
                        if (item.entryTags.BOOKURL) {
                            result += '<a href="' + item.entryTags.BOOKURL + '">' + item.entryTags.BOOKTITLE + '</a>, ';
                        } else {
                            result += '<i>' + item.entryTags.BOOKTITLE + '</i>, ';
                        }
                    }
                    if (item.entryTags.PUBLISHER) {
                        result += '<i>' + item.entryTags.PUBLISHER + '</i>, ';
                    }
                    if (item.entryTags.YEAR) {
                        result += item.entryTags.YEAR + '.';
                    }

                    result += '</td></tr>';
                });

                result += '</table>';

                return result;
            }
        }
    }
};



function formatAuthors (authorsString) {
    var authors = authorsString.split('and');

    if (authors.length > 3) {
        return authors[0] + ' <i>et al.</i>';
    } else {
        return authorsString;
    }
}
