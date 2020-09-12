# min

A Gemini browser for your terminal.

<img src="demo.gif"/>

## Features

* Vim style keyboard navigation
* Easy to understand implementation - one file, 1500 lines
* Client certificate support
* History (saved to TSV file)
* Bookmarks (saved to TSV file)

## Help

## Navigation

```
n/Tab            Next link / option
Ctrl-O/Shift+Tab Previous link / option
Enter            Navigate to selected link
H                Navigate backwards in history
L                Navigate forwards in history
Esc              Exit
```

### Features

```
b                Toggle bookmark
B                View bookmarks
Ctrl-H           View history
?                View help
```

### Scrolling

```
g                Scroll to top of document
G                Scroll to end of document
←/h              Scroll left
↓/j              Scroll down
↑/k              Scroll up
→/l              Scroll right
Home             Scroll home horizontally
End              Scroll end horizontally
Ctrl-U           Scroll up half a screen
Ctrl-D           Scroll down half a screen
```

## Configuration

### config.ini

* Stored at $HOME/.min/config.ini
* Consists of key/value pairs (e.g. "width=80")
* Contains previously accepted server certificates
* Contains links to client certificates, stored in the same directory

## history.tsv

* Stores previously visited URLs

## boomarks.tsv

* Stores bookmarks
