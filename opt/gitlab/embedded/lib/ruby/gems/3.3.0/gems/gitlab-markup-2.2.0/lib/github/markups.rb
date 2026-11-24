require "github/markup/rdoc"
require "shellwords"

markup(:redcloth, /textile/) do |content|
  RedCloth.new(content).to_html
end

markups << GitHub::Markup::RDoc.new

markup('org-ruby', /org/) do |content|
  Orgmode::Parser.new(content, {
                        :allow_include_files => false,
                        :skip_syntax_highlight => true
                      }).to_html
end

markup(:creole, /creole/) do |content|
  Creole.creolize(content)
end

markup(:wikicloth, /mediawiki|wiki/) do |content|
  wikicloth = WikiCloth::WikiCloth.new(:data => content)
  WikiCloth::WikiBuffer::HTMLElement::ESCAPED_TAGS << 'tt'
  wikicloth.to_html(:noedit => true)
end

command(
  "python3 #{Shellwords.escape(File.dirname(__FILE__))}/commands/rest2html",
  /re?st(\.txt)?/,
  "restructuredtext"
)
