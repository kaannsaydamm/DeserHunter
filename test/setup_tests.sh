#!/bin/bash

# Create a fake PNG file containing PHP code (Magic Byte Test)
echo "Creating fake image.png with hidden PHP code..."
echo -e "\x89PNG\r\n\x1a\n<?php unserialize(\$_GET['p']); ?>" > test/image.png

# Create a fake text file with PHP
echo "Creating note.txt with hidden PHP code..."
echo "This is just a note. <?php unserialize(\$_GET['x']); ?>" > test/note.txt

echo "Test files created in test/ directory."
