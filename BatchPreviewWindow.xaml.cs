using System.Windows;
using UniFiDnsManager.Models;
using UniFiDnsManager.Services;

namespace UniFiDnsManager;

public partial class BatchPreviewWindow : Window
{
    public BatchPreviewWindow(BatchPreview preview)
    {
        InitializeComponent();
        HeadingText.Text = "批量新增 DNS 规则预览";
        DescriptionText.Text = "将按记录类型逐条调用 UniFi 官方 DNS Policy 创建接口。";
        SetMetric(Metric1Label, Metric1Value, "待新增", preview.Pending.Count.ToString());
        SetMetric(Metric2Label, Metric2Value, "UCG 已存在", preview.Existing.Count.ToString());
        SetMetric(Metric3Label, Metric3Value, "输入重复", preview.DuplicateInput.Count.ToString());
        SetMetric(Metric4Label, Metric4Value, "无效", preview.Invalid.Count.ToString());
        PrimaryGroup.Header = "将新增";
        PrimaryList.ItemsSource = preview.Pending.Select(ImportService.Describe).ToList();
        ExistingList.ItemsSource = preview.Existing.Select(ImportService.Describe).ToList();
        InvalidList.ItemsSource = preview.Invalid;
        ExistingGroup.Visibility = preview.Existing.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        InvalidGroup.Visibility = preview.Invalid.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        WarningText.Text = preview.Pending.Count > 0
            ? "执行前会自动保存完整 DNS 快照。官方 API 没有单请求批量端点，程序会逐条提交。"
            : "没有需要新增的记录。";
        ApplyButton.Content = $"新增 {preview.Pending.Count} 条";
        ConfirmCheckBox.IsEnabled = preview.Pending.Count > 0;
        ApplyButton.Tag = preview.Pending.Count;
    }

    public BatchPreviewWindow(IReadOnlyList<DnsRecord> records)
    {
        InitializeComponent();
        HeadingText.Text = "批量删除转发域名预览";
        DescriptionText.Text = "仅删除选中的转发域名记录。";
        SetMetric(Metric1Label, Metric1Value, "将删除", records.Count.ToString());
        SetMetric(Metric2Label, Metric2Value, "类型", "转发域名");
        SetMetric(Metric3Label, Metric3Value, "自动备份", "是");
        SetMetric(Metric4Label, Metric4Value, "可撤销", "是");
        PrimaryGroup.Header = "删除清单";
        PrimaryList.ItemsSource = records.Select(record => record.Key).ToList();
        ExistingGroup.Visibility = Visibility.Collapsed;
        InvalidGroup.Visibility = Visibility.Collapsed;
        WarningText.Text = "执行后这些记录会立即从 UCG Policy Table 删除；程序会先保存完整快照。";
        ApplyButton.Content = $"删除 {records.Count} 条";
        ApplyButton.Style = (Style)FindResource("DangerButton");
        ApplyButton.Tag = records.Count;
    }

    private static void SetMetric(System.Windows.Controls.TextBlock label, System.Windows.Controls.TextBlock value, string labelText, string valueText)
    {
        label.Text = labelText;
        value.Text = valueText;
    }

    private void ConfirmCheckBox_Changed(object sender, RoutedEventArgs e) =>
        ApplyButton.IsEnabled = ConfirmCheckBox.IsChecked == true && Convert.ToInt32(ApplyButton.Tag) > 0;

    private void ApplyButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
