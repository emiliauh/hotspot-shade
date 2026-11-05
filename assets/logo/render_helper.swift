import AppKit
import ImageIO

func bitmapRep(width: Int, height: Int, alpha: Bool) -> NSBitmapImageRep? {
    return NSBitmapImageRep(bitmapDataPlanes: nil,
                            pixelsWide: width, pixelsHigh: height,
                            bitsPerSample: 8,
                            samplesPerPixel: alpha ? 4 : 3,
                            hasAlpha: alpha,
                            isPlanar: false,
                            colorSpaceName: .deviceRGB,
                            bytesPerRow: 0,
                            bitsPerPixel: 0)
}

func opaque(input: String, output: String) {
    let inURL = URL(fileURLWithPath: input)
    guard let source = CGImageSourceCreateWithURL(inURL as CFURL, nil),
          let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
        FileHandle.standardError.write("cannot read \(input)\n".data(using: .utf8)!)
        exit(1)
    }
    let w = image.width
    let h = image.height
    guard let space = CGColorSpace(name: CGColorSpace.sRGB),
          let ctx = CGContext(data: nil, width: w, height: h,
                              bitsPerComponent: 8, bytesPerRow: w * 4,
                              space: space,
                              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else {
        FileHandle.standardError.write("cannot create sRGB context\n".data(using: .utf8)!)
        exit(1)
    }
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
    guard let flat = ctx.makeImage() else { exit(1) }
    let outURL = URL(fileURLWithPath: output)
    guard let dest = CGImageDestinationCreateWithURL(outURL as CFURL,
                                                     "public.png" as CFString, 1, nil) else {
        exit(1)
    }
    CGImageDestinationAddImage(dest, flat, nil)
    guard CGImageDestinationFinalize(dest) else { exit(1) }
    print("opaque \(output) \(w)x\(h)")
}

func fill(_ ctx: CGContext, _ rect: CGRect, _ color: NSColor) {
    ctx.setFillColor(color.cgColor)
    ctx.fill(rect)
}

func yTop(_ top: CGFloat, _ height: CGFloat, _ sheetHeight: Int) -> CGFloat {
    CGFloat(sheetHeight) - top - height
}

func drawImage(_ ctx: CGContext, path: String, x: CGFloat, top: CGFloat,
               size: CGFloat, sheetHeight: Int, shadow: Bool) {
    guard let image = NSImage(contentsOfFile: path) else {
        FileHandle.standardError.write("cannot read \(path)\n".data(using: .utf8)!)
        return
    }
    let rect = CGRect(x: x, y: yTop(top, size, sheetHeight), width: size, height: size)
    ctx.saveGState()
    if shadow {
        ctx.setShadow(offset: CGSize(width: 0, height: -9), blur: 20,
                      color: NSColor.black.withAlphaComponent(0.18).cgColor)
    }
    image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 1.0,
               respectFlipped: false,
               hints: [.interpolation: NSImageInterpolation.high.rawValue])
    ctx.restoreGState()
}

func drawText(_ text: String, x: CGFloat, top: CGFloat, size: CGFloat,
              weight: NSFont.Weight, color: NSColor, sheetHeight: Int) {
    let attrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.systemFont(ofSize: size, weight: weight),
        .foregroundColor: color
    ]
    let string = NSAttributedString(string: text, attributes: attrs)
    let h = string.size().height
    string.draw(at: NSPoint(x: x, y: yTop(top, h, sheetHeight)))
}

func sheet(output: String, inputs: [String]) {
    let W = 1200, H = 640
    guard let rep = bitmapRep(width: W, height: H, alpha: true),
          let gc = NSGraphicsContext(bitmapImageRep: rep) else { exit(1) }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = gc
    let ctx = gc.cgContext

    let ink = NSColor(srgbRed: 0.043, green: 0.071, blue: 0.125, alpha: 1)
    let muted = NSColor(srgbRed: 0.357, green: 0.400, blue: 0.482, alpha: 1)
    fill(ctx, CGRect(x: 0, y: 0, width: W, height: H),
         NSColor(srgbRed: 0.961, green: 0.969, blue: 0.980, alpha: 1))

    drawText("HotspotShade logo directions", x: 30, top: 16, size: 20,
             weight: .semibold, color: ink, sheetHeight: H)
    drawText("Night Signal, B, is the production direction. Shown at 340, 120, 40, 29 and 16 px.",
             x: 30, top: 44, size: 11, weight: .regular, color: muted, sheetHeight: H)

    let names = ["Signal Tile", "Night Signal", "Monogram H"]
    let labels = ["A", "B", "C"]
    for (i, path) in inputs.prefix(3).enumerated() {
        let x = CGFloat(30 + i * 400)
        drawText(labels[i], x: x + 4, top: 70, size: 24, weight: .bold,
                 color: ink, sheetHeight: H)
        drawText(names[i], x: x + 30, top: 79, size: 13, weight: .medium,
                 color: muted, sheetHeight: H)

        drawImage(ctx, path: path, x: x + 20, top: 108, size: 340,
                  sheetHeight: H, shadow: true)

        let smallTop: CGFloat = 470
        let sizes: [CGFloat] = [120, 40, 29, 16]
        var sx = x + 20
        for s in sizes {
            drawImage(ctx, path: path, x: sx,
                      top: smallTop + (120 - s) / 2, size: s,
                      sheetHeight: H, shadow: false)
            sx += s + 18
        }
        drawText("120 / 40 / 29 / 16 px", x: x + 20, top: 600, size: 10,
                 weight: .regular, color: muted, sheetHeight: H)
    }

    NSGraphicsContext.restoreGraphicsState()
    guard let data = rep.representation(using: .png, properties: [:]) else { exit(1) }
    do { try data.write(to: URL(fileURLWithPath: output)) }
    catch { exit(1) }
    print("sheet \(output)")
}

func downsample(_ image: CGImage, _ size: Int, space: CGColorSpace) -> CGImage? {
    guard let ctx = CGContext(data: nil, width: size, height: size,
                              bitsPerComponent: 8, bytesPerRow: size * 4,
                              space: space,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        return nil
    }
    ctx.interpolationQuality = .high
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: size, height: size))
    return ctx.makeImage()
}

func backgrounds(output: String, input: String) {
    let W = 960, H = 900
    guard let rep = bitmapRep(width: W, height: H, alpha: true),
          let gc = NSGraphicsContext(bitmapImageRep: rep),
          let space = CGColorSpace(name: CGColorSpace.sRGB),
          let source = CGImageSourceCreateWithURL(URL(fileURLWithPath: input) as CFURL, nil),
          let icon = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
        FileHandle.standardError.write("cannot read \(input)\n".data(using: .utf8)!)
        exit(1)
    }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = gc
    let ctx = gc.cgContext

    func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> CGColor {
        return CGColor(colorSpace: space, components: [r, g, b, 1])!
    }
    func fill(_ rect: CGRect, _ color: CGColor) {
        ctx.setFillColor(color)
        ctx.fill(rect)
    }

    fill(CGRect(x: 0, y: 450, width: W, height: 450),
         rgb(0.961, 0.969, 0.980))
    fill(CGRect(x: 0, y: 0, width: W, height: 450),
         rgb(0.035, 0.051, 0.090))

    let ink = NSColor(srgbRed: 0.043, green: 0.071, blue: 0.125, alpha: 1)
    let mutedLight = NSColor(srgbRed: 0.357, green: 0.400, blue: 0.482, alpha: 1)
    let mutedDark = NSColor(srgbRed: 0.898, green: 0.929, blue: 0.976, alpha: 0.62)

    func label(_ text: String, x: CGFloat, top: CGFloat, size: CGFloat,
               weight: NSFont.Weight, color: NSColor) {
        let a = NSAttributedString(string: text, attributes: [
            .font: NSFont.systemFont(ofSize: size, weight: weight),
            .foregroundColor: color])
        a.draw(at: NSPoint(x: x, y: CGFloat(H) - top - a.size().height))
    }

    label("HotspotShade icon, Night Signal", x: 40, top: 26, size: 20,
          weight: .semibold, color: ink)
    label("Light and dark backgrounds. Sizes 340, 120, 40, 29 and 16 px. The 16 px copy is repeated at 8x with nearest sampling.",
          x: 40, top: 56, size: 11, weight: .regular, color: mutedLight)

    func row(title: String, yBase: CGFloat, tint: NSColor, muted: NSColor) {
        label(title, x: 40, top: CGFloat(H) - yBase - 366, size: 13,
              weight: .medium, color: tint)
        var x: CGFloat = 40
        for size in [340, 120, 40, 29, 16] {
            let side = CGFloat(size)
            let y = yBase + (340 - side) / 2
            ctx.saveGState()
            ctx.interpolationQuality = .high
            ctx.draw(icon, in: CGRect(x: x, y: y, width: side, height: side))
            ctx.restoreGState()
            label("\(size) px", x: x, top: CGFloat(H) - yBase + 24, size: 11,
                  weight: .medium, color: muted)
            x += side + 30
        }
        if let small = downsample(icon, 16, space: space) {
            ctx.saveGState()
            ctx.interpolationQuality = .none
            ctx.draw(small, in: CGRect(x: x + 20, y: yBase + 106, width: 128, height: 128))
            ctx.restoreGState()
            label("16 px at 8x", x: x + 20, top: CGFloat(H) - yBase + 24, size: 11,
                  weight: .medium, color: muted)
        }
    }

    row(title: "Light background  #F5F7FA", yBase: 460, tint: ink, muted: mutedLight)
    row(title: "Dark background  #090D17", yBase: 44, tint: NSColor(srgbRed: 0.898, green: 0.929, blue: 0.976, alpha: 0.92),
        muted: mutedDark)

    NSGraphicsContext.restoreGraphicsState()
    guard let data = rep.representation(using: .png, properties: [:]) else { exit(1) }
    do { try data.write(to: URL(fileURLWithPath: output)) }
    catch { exit(1) }
    print("backgrounds \(output)")
}

let args = CommandLine.arguments
if args.count >= 2, args[1] == "opaque", args.count == 4 {
    opaque(input: args[2], output: args[3])
} else if args.count == 4, args[1] == "backgrounds" {
    backgrounds(output: args[2], input: args[3])
} else if args.count >= 6, args[1] == "sheet" {
    sheet(output: args[2], inputs: Array(args.dropFirst(3)))
} else {
    FileHandle.standardError.write("usage: render_helper.swift opaque IN OUT | backgrounds OUT IN | sheet OUT A B C\n".data(using: .utf8)!)
    exit(2)
}
