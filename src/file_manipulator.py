import os
from src.filler import Filler
from src.llm import LLM
from commonforms import prepare_form
import logging
from pathlib import Path

# Only configure logging if not already configured
logger = logging.getLogger(__name__)
if not logger.handlers:
    # Configure logging only once
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


class FileManipulator:
    def __init__(self):
        self.filler = Filler()
        self.llm = LLM()

    def create_template(self, pdf_path: str):
        """
        By using commonforms, we create an editable .pdf template and we store it.
        """
        template_path = Path(pdf_path).parent / f"{Path(pdf_path).stem}_template.pdf"
        prepare_form(pdf_path, template_path)
        return str(template_path)

    def fill_form(self, user_input: str, fields: list, pdf_form_path: str):
        """
        It receives the raw data, runs the PDF filling logic,
        and returns the path to the newly created file.
        """
        # Input validation
        if user_input is None:
            raise ValueError("User input cannot be None")
        if fields is None:
            raise ValueError("Fields cannot be None")
        if pdf_form_path is None:
            raise ValueError("PDF form path cannot be None")
        
        if not isinstance(user_input, str):
            raise TypeError("User input must be a string")
        if not isinstance(fields, (list, dict)):
            raise TypeError("Fields must be a list or dictionary")
        if not isinstance(pdf_form_path, str):
            raise TypeError("PDF form path must be a string")
        
        if not user_input.strip():
            raise ValueError("User input cannot be empty")
        if not fields:
            raise ValueError("Fields cannot be empty")
        if not pdf_form_path.strip():
            raise ValueError("PDF form path cannot be empty")

        logger.info("Received request from frontend")
        logger.info(f"PDF template path: {pdf_form_path}")

        if not os.path.exists(pdf_form_path):
            logger.error(f"PDF template not found at {pdf_form_path}")
            raise FileNotFoundError(f"PDF template not found at {pdf_form_path}")

        # Check PDF file extension
        if not pdf_form_path.lower().endswith('.pdf'):
            raise ValueError("File must be a PDF")

        logger.info("Starting extraction and PDF filling process")
        try:
            # Check file size (prevent memory exhaustion)
            file_size = os.path.getsize(pdf_form_path)
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                raise ValueError("PDF file too large (max 100MB)")
            
            # Check file permissions
            if not os.access(pdf_form_path, os.R_OK):
                raise PermissionError("Cannot read PDF file")
            
            # Use existing LLM instance with updated parameters
            self.llm._transcript_text = user_input
            self.llm._target_fields = fields
            
            output_name = self.filler.fill_form(pdf_form=pdf_form_path, llm=self.llm)

            logger.info("Process completed successfully")
            logger.info(f"Output saved to: {output_name}")

            return output_name

        except (ValueError, RuntimeError, OSError, PermissionError) as e:
            logger.error(f"PDF generation failed: {e}", exc_info=True)
            raise ValueError("PDF generation failed") from e
        except Exception as e:
            logger.error(f"Unexpected error during PDF generation: {e}", exc_info=True)
            raise RuntimeError("PDF generation failed") from e
