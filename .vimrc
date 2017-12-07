source ~/.vimrc

colo github

let NERDTreeIgnore = ['cbcmac-tag$', 'cbcmac-validate$', 'lock$',
                    \ 'rsa-keygen$', 'rsa-sign$', 'rsa-validate$', 'unlock$',
                    \ 'Session.vim$']

autocmd VimLeave * NERDTreeClose
autocmd VimLeave * mksession!

autocmd StdinReadPre * let s:std_in=1
autocmd VimEnter * if argc() == 0 && !exists("s:std_in") | NERDTree | endif
