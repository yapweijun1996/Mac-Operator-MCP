#import <Foundation/Foundation.h>
#import <Vision/Vision.h>
#import <ImageIO/ImageIO.h>
#include "gui-marker-geometry.h"

static NSDictionary *markerBox(CGRect box) {
  return @{ @"x": @(box.origin.x), @"y": @(box.origin.y), @"width": @(box.size.width), @"height": @(box.size.height) };
}
static MbaMarkerBox geometry(NSDictionary *token) {
  NSDictionary *box = token[@"bbox"];
  return (MbaMarkerBox){ [box[@"x"] doubleValue], [box[@"y"] doubleValue], [box[@"width"] doubleValue], [box[@"height"] doubleValue] };
}

// Reads an already-authorized fixture screenshot only. It has no AX, capture,
// application-control or permission APIs, and never emits recognized UI text.
int main(int argc, const char *argv[]) {
  @autoreleasepool {
    BOOL diagnostics = argc == 2 && strcmp(argv[1], "--diagnostics") == 0;
    if (argc != 1 && !diagnostics) return 64;
    NSMutableData *image = [NSMutableData data];
    for (;;) {
      NSData *chunk = [NSFileHandle.fileHandleWithStandardInput readDataOfLength:8192];
      if (chunk.length == 0) break;
      if (image.length + chunk.length > 480000) return 65;
      [image appendData:chunk];
    }
    if (image.length == 0) return 65;
    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)image, NULL);
    if (source == NULL) return 65;
    NSDictionary *properties = CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source, 0, NULL));
    CFRelease(source);
    double imageWidth = [properties[(__bridge NSString *)kCGImagePropertyPixelWidth] doubleValue];
    double imageHeight = [properties[(__bridge NSString *)kCGImagePropertyPixelHeight] doubleValue];
    if (!isfinite(imageWidth) || !isfinite(imageHeight) || imageWidth <= 0 || imageHeight <= 0 || imageWidth > 1600 || imageHeight > 1600) return 65;
    VNRecognizeTextRequest *request = [VNRecognizeTextRequest new];
    request.recognitionLevel = VNRequestTextRecognitionLevelAccurate;
    request.usesLanguageCorrection = NO;
    request.recognitionLanguages = @[@"en-US"];
    request.customWords = @[@"MBA-MCP"];
    VNImageRequestHandler *handler = [[VNImageRequestHandler alloc] initWithData:image options:@{}];
    NSError *error = nil;
    if (![handler performRequests:@[request] error:&error]) return 66;
    BOOL present = NO, exactCandidate = NO, normalizedCandidate = NO, prefixCandidate = NO, testCandidate = NO;
    float exactConfidence = 0, normalizedConfidence = 0, prefixConfidence = 0, testConfidence = 0;
    NSUInteger candidates = 0;
    NSMutableArray<NSDictionary *> *prefixTokens = [NSMutableArray new], *testTokens = [NSMutableArray new];
    for (VNRecognizedTextObservation *observation in request.results) {
      for (VNRecognizedText *candidate in [observation topCandidates:3]) {
        candidates++;
        NSString *text = candidate.string.lowercaseString;
        NSString *normalized = [[text componentsSeparatedByCharactersInSet:NSCharacterSet.alphanumericCharacterSet.invertedSet]
          componentsJoinedByString:@""];
        BOOL exact = [text containsString:@"mba-mcp test"];
        BOOL normalizedMatch = [normalized containsString:@"mbamcptest"];
        BOOL prefix = [normalized containsString:@"mbamcp"];
        BOOL test = [text rangeOfString:@"\\btest\\b" options:NSRegularExpressionSearch].location != NSNotFound;
        if (exact) { exactCandidate = YES; exactConfidence = MAX(exactConfidence, candidate.confidence); }
        if (normalizedMatch) { normalizedCandidate = YES; normalizedConfidence = MAX(normalizedConfidence, candidate.confidence); }
        if (prefix) { prefixCandidate = YES; prefixConfidence = MAX(prefixConfidence, candidate.confidence); }
        if (test) { testCandidate = YES; testConfidence = MAX(testConfidence, candidate.confidence); }
        if (exact && candidate.confidence >= 0.5) present = YES;
        // Only complete, known tokens qualify. A title containing the prefix
        // plus other words cannot supply half of a document marker.
        NSString *token = [normalized isEqualToString:@"mbamcp"] ? @"prefix" : [normalized isEqualToString:@"test"] ? @"test" : nil;
        if (token != nil) {
          NSMutableArray *tokens = [token isEqualToString:@"prefix"] ? prefixTokens : testTokens;
          if (tokens.count < 32) [tokens addObject:@{ @"token": token, @"confidence": @(candidate.confidence),
            @"bbox": markerBox(observation.boundingBox) }];
        }
      }
    }
    NSDictionary *adjacentPair = nil;
    float adjacentConfidence = 0;
    for (NSDictionary *prefix in prefixTokens) for (NSDictionary *word in testTokens) {
      float confidence = MIN([prefix[@"confidence"] floatValue], [word[@"confidence"] floatValue]);
      if (confidence < 0.5 || !mbaMarkerTokensAdjacentWithAspect(geometry(prefix), geometry(word), imageWidth / imageHeight)) continue;
      if (adjacentPair == nil || confidence > adjacentConfidence) {
        adjacentConfidence = confidence;
        adjacentPair = @{ @"prefix_bbox": prefix[@"bbox"], @"test_bbox": word[@"bbox"], @"confidence": @(confidence) };
      }
    }
    if (adjacentPair != nil) present = YES;
    NSDictionary *output = diagnostics ? @{ @"marker_present": @(present), @"confidence_threshold": @0.5,
      @"image_width": @(imageWidth), @"image_height": @(imageHeight), @"bbox_coordinate_space": @"normalized_image",
      @"observation_count": @(request.results.count), @"candidate_count": @(candidates),
      @"exact_marker_candidate": @(exactCandidate), @"exact_marker_max_confidence": @(exactConfidence),
      @"normalized_marker_candidate": @(normalizedCandidate), @"normalized_marker_max_confidence": @(normalizedConfidence),
      @"known_prefix_candidate": @(prefixCandidate), @"known_prefix_max_confidence": @(prefixConfidence),
      @"known_test_word_candidate": @(testCandidate), @"known_test_word_max_confidence": @(testConfidence),
      @"known_prefix_token_boxes": prefixTokens, @"known_test_token_boxes": testTokens,
      @"same_baseline_adjacent_candidate": @((BOOL)(adjacentPair != nil)),
      @"adjacent_marker_max_confidence": @(adjacentConfidence), @"adjacent_pair": adjacentPair ?: NSNull.null }
      : @{ @"marker_present": @(present) };
    NSData *result = [NSJSONSerialization dataWithJSONObject:output options:0 error:nil];
    if (result == nil) return 67;
    fwrite(result.bytes, 1, result.length, stdout); fputc('\n', stdout);
    return 0;
  }
}
