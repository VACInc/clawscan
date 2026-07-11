//go:build windows

package runner

// Windows has no portable O_NOFOLLOW open flag. The leading lstat regular-file
// guard plus the post-open lstat/fstat same-file check in readPluginID catch a
// symlinked or swapped manifest there without following it.
const openNoFollowFlag = 0
