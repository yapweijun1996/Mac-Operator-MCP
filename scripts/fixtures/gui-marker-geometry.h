#include <stdbool.h>
#include <math.h>

typedef struct { double x, y, width, height; } MbaMarkerBox;

static bool mbaMarkerBoxValid(MbaMarkerBox box) {
  return isfinite(box.x) && isfinite(box.y) && isfinite(box.width) && isfinite(box.height) &&
    box.x >= 0 && box.y >= 0 && box.width > 0 && box.height > 0 &&
    box.x + box.width <= 1 && box.y + box.height <= 1;
}

static bool mbaMarkerTokensAdjacentWithAspect(MbaMarkerBox prefix, MbaMarkerBox word, double imageAspect) {
  if (!mbaMarkerBoxValid(prefix) || !mbaMarkerBoxValid(word) || word.x <= prefix.x ||
      !isfinite(imageAspect) || imageAspect <= 0 || imageAspect > 64) return false;
  double height = fmax(prefix.height, word.height), smallerHeight = fmin(prefix.height, word.height);
  double gap = (word.x - (prefix.x + prefix.width)) * imageAspect;
  double overlap = fmin(prefix.y + prefix.height, word.y + word.height) - fmax(prefix.y, word.y);
  // Vision word boxes can differ slightly in height; require one baseline and
  // at most one glyph-height of whitespace, with only a small box overlap.
  return gap >= -0.1 * smallerHeight && gap <= height &&
    fabs(prefix.y - word.y) <= 0.25 * height &&
    fabs(prefix.y + prefix.height / 2 - word.y - word.height / 2) <= 0.4 * height &&
    overlap >= 0.5 * smallerHeight;
}

static bool mbaMarkerTokensAdjacent(MbaMarkerBox prefix, MbaMarkerBox word) {
  return mbaMarkerTokensAdjacentWithAspect(prefix, word, 1);
}
