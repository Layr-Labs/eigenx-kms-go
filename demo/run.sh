#!/usr/bin/env bash

SESSION_NAME="kms-demo"

# Start a new tmux session (detached) with a larger virtual size
tmux new-session -d -s $SESSION_NAME -x 200 -y 50

# Split into two columns (vertical split) - this targets the only pane (0)
tmux split-window -h -t $SESSION_NAME:0.0

# Now we have pane 0 (left) and pane 1 (right)
# Split ONLY pane 1 (the right pane) vertically 4 times
tmux split-window -v -t $SESSION_NAME:0.1
tmux split-window -v -t $SESSION_NAME:0.1
tmux split-window -v -t $SESSION_NAME:0.1
tmux split-window -v -t $SESSION_NAME:0.1

# Use main-vertical layout and then adjust
tmux select-layout -t $SESSION_NAME main-vertical

# Now manually select each right pane and make them equal
# by selecting the layout that works best
tmux select-pane -t $SESSION_NAME:0.1
tmux select-layout -t $SESSION_NAME "$(tmux list-windows -t $SESSION_NAME -F '#{window_layout}' | sed 's/\[[0-9]*x[0-9]*,0,0\]/[100x50,0,0]/')"

tmux select-pane -t $SESSION_NAME:0.0

# Run specific scripts in each of the right panes
tmux send-keys -t $SESSION_NAME:0.1 './scripts/runIndexedOperator.sh 1' C-m
tmux send-keys -t $SESSION_NAME:0.2 './scripts/runIndexedOperator.sh 2' C-m
tmux send-keys -t $SESSION_NAME:0.3 './scripts/runIndexedOperator.sh 3' C-m
tmux send-keys -t $SESSION_NAME:0.4 './scripts/runIndexedOperator.sh 4' C-m
tmux send-keys -t $SESSION_NAME:0.5 './scripts/runIndexedOperator.sh 5' C-m

# Attach to the session
tmux attach-session -t $SESSION_NAME
