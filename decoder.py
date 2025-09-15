# The correct, full "pv" string for the puzzle
pv_string = "c1c2 a2a1 c7e5 a1b1 c2b2 b1a1 b2a2 a1b1 a2b2 b1a1 b2b1 a1a2 b1b2 a2a1 b2a1 a1b1 c7b6 b1a2 b6a5 a2b1 a5c7 b1a2 c7b6 a2b1 b6d4 b1a2 d4b6 a2b1 b6a5 b1a2 a5c7 a2b1 c7a5 b1a2 a5b6 a2b1 b6d4 b1a2 d4c5 a2b1 c5e7 b1a2 e7c5 a2b1 c5d4 b1a2"

# The correctly parsed list of indices for this puzzle
indices = [15, 16, 5, 9, 4, 3, 1, 7, 12, 13, 7, 5, 8, 9, 5, 1, 8, 13, 14, 15, 4, 3, 13, 14, 12, 4, 2, 8, 15, 4, 19, 13, 12, 18, 12, 19, 4, 3, 3, 12, 11, 7, 16, 17, 13, 7, 14, 9, 11, 0, 9, 16, 6, 3, 12, 13, 13, 12, 8, 14, 9, 11, 0, 9, 16, 6, 13, 14, 12, 19, 9, 11, 4, 3, 7, 16, 12, 12, 60, 21, 66, 43, 13, 7, 11, 15, 4, 11, 2]

# Remove spaces from the pv_string to treat it as one long sequence
sequence = pv_string.replace(" ", "")

result = ""
for index in indices:
    result += sequence[index]

print(result)
