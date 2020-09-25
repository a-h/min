# min

A Gemini browser for your terminal.

<img src="demo.gif"/>

## Installation

Download the compiled binary for your platform at https://github.com/a-h/min/releases

If you're using a Raspberry Pi you probably want the ARM v6 binary, even if you're on a Pi 4.

Tested on:

* Mac
* FreeBSD (x86_64)
* Linux (Arm)
  * Pi Zero running Raspbian
  * Pi 4 running Ubuntu

## Building from source

Requires Go 1.15, but no other build dependencies are required.

```
# requires go 1.15
go build
```

## Features

* Vim style keyboard navigation
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

* Stored in your operating system's default config location under .min, e.g. 
  * Linux: $HOME/config/.min/config.ini
  * Mac: ~/Library/Application Support/.min/config.ini
  * Windows: %AppData%/.min/config.ini
* Consists of key/value pairs (e.g. "width=80")
* Contains previously accepted server certificates
* Contains links to client certificates, stored in the same directory

## history.tsv

* Stores previously visited URLs

## boomarks.tsv

* Stores bookmarks
