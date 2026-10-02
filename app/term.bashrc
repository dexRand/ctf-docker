# StegSuite interactive terminal
export TERM=xterm-256color
export PS1='\[\e[1;35m\]stegsuite\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
export CLICOLOR=1

# colours by file type (directories, executables, symlinks, archives, images…)
if command -v dircolors >/dev/null 2>&1; then
  eval "$(dircolors -b)"
else
  export LS_COLORS='rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:ex=01;32:*.tar=01;31:*.tgz=01;31:*.zip=01;31:*.gz=01;31:*.7z=01;31:*.png=01;35:*.jpg=01;35:*.gif=01;35:*.txt=00;37:*.py=00;33'
fi

alias ls='ls --color=auto'
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias grep='grep --color=auto'
alias please='sudo'
