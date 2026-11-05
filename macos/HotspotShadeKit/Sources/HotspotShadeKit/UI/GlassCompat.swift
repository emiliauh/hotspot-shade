import SwiftUI

// The Liquid Glass helpers. macOS 26 uses glass. macOS 14 and 15 use a
// material. Reduce Transparency always uses an opaque surface.
public extension View {
    @ViewBuilder func hsGlassSurface(cornerRadius: CGFloat = 16, reduceTransparency: Bool = false) -> some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *), !reduceTransparency {
            self.glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            self.hsSurfaceFallback(cornerRadius: cornerRadius, reduceTransparency: reduceTransparency)
        }
        #else
        self.hsSurfaceFallback(cornerRadius: cornerRadius, reduceTransparency: reduceTransparency)
        #endif
    }

    @ViewBuilder func hsSurfaceFallback(cornerRadius: CGFloat = 16, reduceTransparency: Bool = false) -> some View {
        if reduceTransparency {
            self.hsOpaqueSurface(cornerRadius: cornerRadius)
        } else {
            self.hsMaterialSurface(cornerRadius: cornerRadius)
        }
    }

    func hsMaterialSurface(cornerRadius: CGFloat = 16) -> some View {
        self
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous).strokeBorder(.separator, lineWidth: 1))
    }

    // An opaque surface for Reduce Transparency.
    func hsOpaqueSurface(cornerRadius: CGFloat = 16) -> some View {
        self
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous).strokeBorder(.separator, lineWidth: 1))
    }
}

// One glass container for a group of cards on macOS 26. Earlier systems place
// the cards in the same stack without a container.
public struct GlassCardGroup<Content: View>: View {
    public var spacing: CGFloat
    private let content: () -> Content
    public init(spacing: CGFloat = 16, @ViewBuilder content: @escaping () -> Content) {
        self.spacing = spacing
        self.content = content
    }
    public var body: some View {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: spacing) { content() }
        } else {
            content()
        }
        #else
        content()
        #endif
    }
}
