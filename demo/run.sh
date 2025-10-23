#!/usr/bin/env bash

SESSION_NAME="kms-demo"

tmux new-session -d -s $SESSION_NAME

# Split into two columns (vertical split)
tmux split-window -h -t $SESSION_NAME

# Focus on the right pane and split it into 5 equal panes
tmux select-pane -t $SESSION_NAME:0.1

# Split into 5 panes (4 splits total)
tmux split-window -v -t $SESSION_NAME:0.1
tmux split-window -v -t $SESSION_NAME:0.2
tmux split-window -v -t $SESSION_NAME:0.3
tmux split-window -v -t $SESSION_NAME:0.4

tmux select-pane -t $SESSION_NAME:0.1
tmux select-layout -t $SESSION_NAME main-vertical

tmux resize-pane -t $SESSION_NAME:0.0 -x 50%

# Run specific scripts in each of the right panes
tmux send-keys -t $SESSION_NAME:0.1 'echo "1"' C-m
tmux send-keys -t $SESSION_NAME:0.2 'echo "2"' C-m
tmux send-keys -t $SESSION_NAME:0.3 'echo "3"' C-m
tmux send-keys -t $SESSION_NAME:0.4 'echo "4"' C-m


# Attach to the session
tmux attach-session -t $SESSION_NAME
