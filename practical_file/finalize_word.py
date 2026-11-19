"""Uses Microsoft Word (COM) to insert the vector diagram, update the contents,
list of figures and page numbers, and export the PDF.

    .venv\\Scripts\\python.exe practical_file\\finalize_word.py
"""

import os

import win32com.client as win32

HERE = os.path.dirname(os.path.abspath(__file__))
DOCX = os.path.join(HERE, "NetScope_CN_Practical_File.docx")
PDF = os.path.join(HERE, "NetScope_CN_Practical_File.pdf")
SVG = os.path.join(HERE, "figures", "00_architecture.svg")
PNG = os.path.join(HERE, "figures", "00_architecture.png")

word = win32.DispatchEx("Word.Application")
word.Visible = False
word.DisplayAlerts = 0
try:
    doc = word.Documents.Open(DOCX)
    rng = doc.Content
    find = rng.Find
    if find.Execute(FindText="[[ARCH_SVG]]"):
        rng.Text = ""
        try:
            shape = doc.InlineShapes.AddPicture(SVG, False, True, rng)
            print("inserted SVG (vector)")
        except Exception as exc:  # older Word without SVG support
            shape = doc.InlineShapes.AddPicture(PNG, False, True, rng)
            print("SVG insert failed, used PNG:", exc)
        width_pt = 16 * 28.3465
        ratio = shape.Height / shape.Width
        shape.Width = width_pt
        shape.Height = width_pt * ratio
    else:
        print("placeholder not found (already finalized?)")

    for _ in range(2):  # second pass picks up page numbers after the TOC grows
        doc.Fields.Update()
        for toc in doc.TablesOfContents:
            toc.Update()
    doc.Save()
    doc.ExportAsFixedFormat(PDF, 17)  # wdExportFormatPDF
    print("pages:", doc.ComputeStatistics(2))
    doc.Close(False)
finally:
    word.Quit()
print("saved", DOCX, "and", PDF)
