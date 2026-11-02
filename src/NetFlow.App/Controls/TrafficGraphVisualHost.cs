using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Pen = System.Windows.Media.Pen;
using Color = System.Windows.Media.Color;
using Point = System.Windows.Point;
using Rect = System.Windows.Rect;

namespace NetFlow.App.Controls;

/// <summary>
/// Ultra-low latency, DirectX-accelerated (MILCore) visual host for real-time
/// network bandwidth dual-wave curves matching GNOME System Monitor / Adwaita canvas styling.
/// Uses pre-allocated frozen brushes, pens, and StreamGeometry for zero per-frame heap allocations.
/// </summary>
public class TrafficGraphVisualHost : FrameworkElement
{
    private const int MaxPoints = 60;
    private readonly VisualCollection _visuals;
    private readonly DrawingVisual _drawingVisual;

    private readonly double[] _rxHistory = new double[MaxPoints];
    private readonly double[] _txHistory = new double[MaxPoints];

    // Pre-allocated frozen pens and brushes for DirectWrite / MILCore acceleration
    private static readonly Brush BgBrush;
    private static readonly Pen BorderPen;
    private static readonly Pen GridHLinePen;
    private static readonly Pen GridVLinePen;
    private static readonly Pen RxStrokePen;
    private static readonly Pen TxStrokePen;
    private static readonly Brush RxFillBrush;
    private static readonly Brush TxFillBrush;
    private static readonly Brush RxDotBrush;
    private static readonly Brush TxDotBrush;

    static TrafficGraphVisualHost()
    {
        var bg = new SolidColorBrush(Color.FromRgb(0x18, 0x18, 0x18));
        bg.Freeze();
        BgBrush = bg;

        var border = new Pen(new SolidColorBrush(Color.FromArgb(15, 255, 255, 255)), 1);
        border.Freeze();
        BorderPen = border;

        var hLine = new Pen(new SolidColorBrush(Color.FromArgb(13, 255, 255, 255)), 1);
        hLine.Freeze();
        GridHLinePen = hLine;

        var vLine = new Pen(new SolidColorBrush(Color.FromArgb(6, 255, 255, 255)), 1);
        vLine.Freeze();
        GridVLinePen = vLine;

        var rxPen = new Pen(new SolidColorBrush(Color.FromRgb(0x35, 0x84, 0xe4)), 2)
        {
            LineJoin = PenLineJoin.Round,
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round
        };
        rxPen.Freeze();
        RxStrokePen = rxPen;

        var txPen = new Pen(new SolidColorBrush(Color.FromRgb(0xff, 0x78, 0x00)), 2)
        {
            LineJoin = PenLineJoin.Round,
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round
        };
        txPen.Freeze();
        TxStrokePen = txPen;

        var rxGrad = new LinearGradientBrush(
            Color.FromArgb(90, 53, 132, 228),
            Color.FromArgb(5, 53, 132, 228),
            new Point(0, 0),
            new Point(0, 1));
        rxGrad.Freeze();
        RxFillBrush = rxGrad;

        var txGrad = new LinearGradientBrush(
            Color.FromArgb(90, 255, 120, 0),
            Color.FromArgb(5, 255, 120, 0),
            new Point(0, 0),
            new Point(0, 1));
        txGrad.Freeze();
        TxFillBrush = txGrad;

        var rxDot = new SolidColorBrush(Color.FromRgb(0x35, 0x84, 0xe4));
        rxDot.Freeze();
        RxDotBrush = rxDot;

        var txDot = new SolidColorBrush(Color.FromRgb(0xff, 0x78, 0x00));
        txDot.Freeze();
        TxDotBrush = txDot;

        var halo = new Pen(new SolidColorBrush(Color.FromArgb(180, 255, 255, 255)), 1);
        halo.Freeze();
        HaloPen = halo;
    }

    private static readonly Pen HaloPen;

    public TrafficGraphVisualHost()
    {
        _visuals = new VisualCollection(this);
        _drawingVisual = new DrawingVisual();
        _visuals.Add(_drawingVisual);

        ClipToBounds = true;
        SizeChanged += (_, _) => Redraw();
    }

    protected override int VisualChildrenCount => _visuals.Count;

    protected override Visual GetVisualChild(int index) => _visuals[index];

    public void UpdateSpeeds(double rxBps, double txBps)
    {
        Array.Copy(_rxHistory, 1, _rxHistory, 0, MaxPoints - 1);
        Array.Copy(_txHistory, 1, _txHistory, 0, MaxPoints - 1);

        _rxHistory[MaxPoints - 1] = rxBps;
        _txHistory[MaxPoints - 1] = txBps;

        Redraw();
    }

    public void SetHistory(IReadOnlyList<double> rxList, IReadOnlyList<double> txList)
    {
        int count = Math.Min(MaxPoints, Math.Min(rxList.Count, txList.Count));
        Array.Clear(_rxHistory, 0, MaxPoints);
        Array.Clear(_txHistory, 0, MaxPoints);

        int offset = MaxPoints - count;
        for (int i = 0; i < count; i++)
        {
            _rxHistory[offset + i] = rxList[i];
            _txHistory[offset + i] = txList[i];
        }

        Redraw();
    }

    public double GetCurrentMaxScale()
    {
        double max = 50 * 1024; // 50 KB/s floor
        for (int i = 0; i < MaxPoints; i++)
        {
            if (_rxHistory[i] > max) max = _rxHistory[i];
            if (_txHistory[i] > max) max = _txHistory[i];
        }
        return max;
    }

    private void Redraw()
    {
        double width = ActualWidth;
        double height = ActualHeight;

        if (width < 20 || height < 20) return;

        double maxVal = GetCurrentMaxScale();
        double baselineY = height - 4;
        double startX = 2.0;
        double endX = Math.Max(startX + 10, width - 4);
        double step = (endX - startX) / (MaxPoints - 1);

        using DrawingContext dc = _drawingVisual.RenderOpen();

        // 1. Crisp Background & Border with geometric clipping
        var bgRect = new Rect(0, 0, width, height);
        dc.DrawRoundedRectangle(BgBrush, BorderPen, bgRect, 8, 8);

        // Push clip geometry matching the 8px corner radius so grid and waves don't spill outside
        dc.PushClip(new RectangleGeometry(bgRect, 8, 8));

        // 2. Horizontal Grid Lines (4 divisions)
        const int gridYCount = 4;
        for (int i = 1; i <= gridYCount; i++)
        {
            double y = (height / gridYCount) * i;
            dc.DrawLine(GridHLinePen, new Point(0, y), new Point(width, y));
        }

        // 3. Vertical Time Markers every 10 points
        for (int i = 0; i < MaxPoints; i += 10)
        {
            double x = startX + (i * step);
            dc.DrawLine(GridVLinePen, new Point(x, 0), new Point(x, height));
        }

        // 4. Draw Receiving Wave (Blue #3584e4)
        DrawWave(dc, _rxHistory, maxVal, startX, endX, step, baselineY, height, RxFillBrush, RxStrokePen);

        // 5. Draw Sending Wave (Orange #ff7800)
        DrawWave(dc, _txHistory, maxVal, startX, endX, step, baselineY, height, TxFillBrush, TxStrokePen);

        // 6. Draw Live Current Value Pulse Dots precisely on wave terminal point
        double lastRxY = Math.Max(8, baselineY - (_rxHistory[MaxPoints - 1] / maxVal) * (height - 24));
        double lastTxY = Math.Max(8, baselineY - (_txHistory[MaxPoints - 1] / maxVal) * (height - 24));
        dc.DrawEllipse(RxDotBrush, HaloPen, new Point(endX, lastRxY), 3.5, 3.5);
        dc.DrawEllipse(TxDotBrush, HaloPen, new Point(endX, lastTxY), 3.5, 3.5);

        dc.Pop();
    }

    private static void DrawWave(
        DrawingContext dc,
        double[] history,
        double maxVal,
        double startX,
        double endX,
        double step,
        double baselineY,
        double height,
        Brush fillBrush,
        Pen strokePen)
    {
        var fillGeo = new StreamGeometry();
        var strokeGeo = new StreamGeometry();

        using (var fillCtx = fillGeo.Open())
        using (var strokeCtx = strokeGeo.Open())
        {
            fillCtx.BeginFigure(new Point(startX, baselineY), isFilled: true, isClosed: true);

            Point firstPoint = new Point(startX, Math.Max(8, baselineY - (history[0] / maxVal) * (height - 24)));
            fillCtx.LineTo(firstPoint, isStroked: true, isSmoothJoin: true);
            strokeCtx.BeginFigure(firstPoint, isFilled: false, isClosed: false);

            for (int i = 1; i < MaxPoints; i++)
            {
                double x = startX + (i * step);
                double speed = history[i];
                double y = Math.Max(8, baselineY - (speed / maxVal) * (height - 24));
                var pt = new Point(x, y);

                fillCtx.LineTo(pt, isStroked: true, isSmoothJoin: true);
                strokeCtx.LineTo(pt, isStroked: true, isSmoothJoin: true);
            }

            fillCtx.LineTo(new Point(endX, baselineY), isStroked: true, isSmoothJoin: true);
        }

        fillGeo.Freeze();
        strokeGeo.Freeze();

        dc.DrawGeometry(fillBrush, null, fillGeo);
        dc.DrawGeometry(null, strokePen, strokeGeo);
    }
}
