%% cas-dc.cls - Elsevier CAS double column compatibility class
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{cas-dc}[2024/01/01 Elsevier CAS Double Column Class]

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\ProcessOptions\relax

\LoadClass[a4paper,10pt,twocolumn]{article}

\RequirePackage{geometry}
\geometry{margin=1.5cm, top=2cm, bottom=2cm}

\RequirePackage{etoolbox}
\RequirePackage{environ}
\RequirePackage{xcolor}

\newcommand{\shorttitle}[1]{\def\@shorttitle{#1}}
\newcommand{\shortauthors}[1]{\def\@shortauthors{#1}}
\newcommand{\cormark}[1]{$^*$}
\newcommand{\ead}[1]{\def\@ead{#1}}
\newcommand{\address}[2][]{\def\@address{#2}}
\newcommand{\cortext}[2][]{\def\@cortext{#2}}
\renewcommand{\author}[2][]{\def\@author{#2}}

\NewEnviron{keywords}{\small\textbf{Keywords:} \BODY}

\renewcommand{\maketitle}{%
  \twocolumn[%
    \begin{center}%
      {\LARGE \bfseries \@title \par}%
      \vskip 1em%
      {\large \@author \cormark[1] \par}%
      \vskip 0.5em%
      {\small Email: \texttt{\@ead} \par}%
      \vskip 0.5em%
      {\small \@address \par}%
      \vskip 1em%
    \end{center}%
  ]%
}