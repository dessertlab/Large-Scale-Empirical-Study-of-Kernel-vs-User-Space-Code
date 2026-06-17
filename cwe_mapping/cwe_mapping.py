import xml.etree.ElementTree as ET
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

class CWENavigator:
    def __init__(self, xml_file_path: str):
        """
        Initializes the navigator with the CWE XML file.
        
        Args:
            xml_file_path: Path to the cwec_latest.xml file downloaded from MITRE
        """
        self.tree = ET.parse(xml_file_path)
        self.root = self.tree.getroot()
        
        # Namespace used in the MITRE XML file
        self.ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        
        # Dictionaries to store entities
        self.weaknesses: Dict[str, ET.Element] = {}
        self.categories: Dict[str, ET.Element] = {}
        self.views: Dict[str, ET.Element] = {}
        
        # Parent relations (ChildOf)
        self.child_of: Dict[str, List[str]] = defaultdict(list)
        
        # View structure: view_id -> {parent_id -> [children_ids]}
        self.view_structure: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        
        # Parent->child map for reverse navigation
        self.view_parent_map: Dict[str, Dict[str, str]] = defaultdict(dict)
        
        self._parse_xml()
        self._build_view_hierarchies()
    
    def _parse_xml(self):
        """Parses the XML file and builds the basic data structures."""
        
        # Parse Weaknesses
        for weakness in self.root.findall('.//cwe:Weakness', self.ns):
            cwe_id = weakness.get('ID')
            self.weaknesses[cwe_id] = weakness
            
            # Extract ChildOf relations
            for rel in weakness.findall('.//cwe:Related_Weakness', self.ns):
                if rel.get('Nature') == 'ChildOf':
                    parent_id = rel.get('CWE_ID')
                    self.child_of[cwe_id].append(parent_id)
        
        # Parse Categories
        for category in self.root.findall('.//cwe:Category', self.ns):
            cat_id = category.get('ID')
            self.categories[cat_id] = category
            
            # Extract ChildOf relations for categories
            for rel in category.findall('.//cwe:Relationships/cwe:Has_Member', self.ns):
                nature = rel.get('Nature')
                if nature == 'ChildOf':
                    parent_id = rel.get('CWE_ID')
                    self.child_of[cat_id].append(parent_id)
        
        # Parse Views
        for view in self.root.findall('.//cwe:View', self.ns):
            view_id = view.get('ID')
            self.views[view_id] = view
    
    def _build_view_hierarchies(self):
        """
        Builds the complete hierarchy of each View.
        """
        for view_id, view in self.views.items():
            # Collect all direct members of the view
            for member in view.findall('.//cwe:Members/cwe:Has_Member', self.ns):
                member_id = member.get('CWE_ID')
                if member_id:
                    # Add to the structure as a child of the view
                    self.view_structure[view_id][view_id].append(member_id)
                    self.view_parent_map[view_id][member_id] = view_id
                    
                    # If it is a category, process recursively
                    if member_id in self.categories:
                        self._process_category_members(view_id, member_id)
    
    def _process_category_members(self, view_id: str, category_id: str):
        """
        Recursively processes all members of a category.
        """
        if category_id not in self.categories:
            return
        
        category = self.categories[category_id]
        
        # Find all members of this category
        for member in category.findall('.//cwe:Relationships/cwe:Has_Member', self.ns):
            member_id = member.get('CWE_ID')
            
            if not member_id:
                continue
            
            # Add to the structure
            self.view_structure[view_id][category_id].append(member_id)
            self.view_parent_map[view_id][member_id] = category_id
            
            # If it is a category, recurse
            if member_id in self.categories:
                self._process_category_members(view_id, member_id)
    
    def _find_path_in_view(self, view_id: str, cwe_id: str) -> Optional[Tuple[str, ...]]:
        """
        Finds the complete path from the view root up to the specified CWE.
        
        Args:
            view_id: ID of the view
            cwe_id: ID of the CWE to search for
        
        Returns:
            Tuple with the complete path, or None if not found
        """
        if view_id not in self.view_parent_map:
            return None
        
        # If the CWE is not in the view, try searching for it through ChildOf
        if cwe_id not in self.view_parent_map[view_id]:
            # Climb the ChildOf hierarchy to find an ancestor that is in the view
            visited = set()
            current = cwe_id
            
            while current and current not in visited:
                visited.add(current)
                if current in self.view_parent_map[view_id]:
                    # Found an ancestor in the view, build the path
                    path = self._build_path(view_id, current)
                    if path:
                        # Add the original CWE to the end if different
                        if current != cwe_id:
                            return path + (cwe_id,)
                        return path
                    return None
                
                parents = self.child_of.get(current, [])
                if not parents:
                    break
                current = parents[0]
            
            return None
        
        return self._build_path(view_id, cwe_id)
    
    def _build_path(self, view_id: str, cwe_id: str) -> Optional[Tuple[str, ...]]:
        """
        Builds the path from the view root to the CWE by climbing the parent map.
        """
        path = []
        current = cwe_id
        visited = set()
        
        while current and current not in visited:
            visited.add(current)
            path.append(current)
            
            if current == view_id:
                # We reached the root
                break
            
            parent = self.view_parent_map[view_id].get(current)
            if not parent:
                break
            
            current = parent
        
        # Remove the view_id from the path (we only want categories and the CWE)
        if path and path[-1] == view_id:
            path.pop()
        
        # Reverse to have the path from top to bottom
        path.reverse()
        
        return tuple(path) if path else None
    
    def get_top_parent(self, cwe_id: str) -> Optional[str]:
        """
        Finds the highest-level parent by climbing all ChildOf relations.
        
        Args:
            cwe_id: ID of the CWE (e.g., "120")
        
        Returns:
            ID of the highest-level parent, or None if not found
        """
        if cwe_id not in self.child_of and cwe_id not in self.weaknesses and cwe_id not in self.categories:
            return None
        
        visited: Set[str] = set()
        current = cwe_id
        
        while current and current not in visited:
            visited.add(current)
            parents = self.child_of.get(current, [])
            
            if not parents:
                return current if current != cwe_id else None
            
            current = parents[0]
        
        return None
    
    def get_paths_in_views(self, cwe_id: str, view_ids: List[str]) -> Dict[str, Optional[Tuple[str, ...]]]:
        """
        Finds the paths of the CWE in multiple views.
        
        Args:
            cwe_id: ID of the CWE to search for (e.g., "120")
            view_ids: List of View IDs to search in (e.g., ['700', '888'])
        
        Returns:
            Dictionary {view_id: path_tuple}
            where path_tuple is (top_category, ..., subcategory, cwe_id)
            or None if the CWE is not present in the view
        """
        results = {}
        
        for view_id in view_ids:
            if view_id not in self.views:
                results[view_id] = None
                continue
            
            path = self._find_path_in_view(view_id, cwe_id)
            results[view_id] = path
        
        return results
    
    def get_element_name(self, element_id: str) -> str:
        """Gets the name of an element (weakness or category)."""
        if element_id in self.weaknesses:
            return self.weaknesses[element_id].get('Name', 'Unknown')
        elif element_id in self.categories:
            return self.categories[element_id].get('Name', 'Unknown')
        else:
            return 'Unknown'
    
    def get_element_type(self, element_id: str) -> str:
        """Gets the type of an element."""
        if element_id in self.weaknesses:
            return 'Weakness'
        elif element_id in self.categories:
            return 'Category'
        else:
            return 'Unknown'
    
    def print_paths(self, cwe_id: str, paths: Dict[str, Optional[Tuple[str, ...]]]):
        """
        Prints the found paths in a readable format.
        
        Args:
            cwe_id: ID of the searched CWE
            paths: Result of get_paths_in_views
        """
        cwe_name = self.get_element_name(cwe_id)
        cwe_type = self.get_element_type(cwe_id)
        
        print(f"\n{'='*70}")
        print(f"🎯 CWE-{cwe_id}: {cwe_name} ({cwe_type})")
        print(f"{'='*70}")
        
        for view_id, path in paths.items():
            view_name = self.views[view_id].get('Name', 'Unknown') if view_id in self.views else 'Unknown'
            
            print(f"\n📊 View {view_id}: {view_name}")
            
            if path is None:
                print(f"   ❌ CWE not found in this view")
            elif len(path) == 0:
                print(f"   ⚠️  Empty path")
            else:
                print(f"   ✅ Path found ({len(path)} elements):")
                
                for i, element_id in enumerate(path):
                    element_name = self.get_element_name(element_id)
                    element_type = self.get_element_type(element_id)
                    
                    indent = "   " + "  " * i
                    arrow = "└─>" if i == len(path) - 1 else "├─>"
                    
                    icon = "📁" if element_type == "Category" else "📄"
                    highlight = " ⭐" if element_id == cwe_id else ""
                    
                    print(f"{indent}{arrow} {icon} CWE-{element_id}: {element_name}{highlight}")
    
    def print_hierarchy(self, cwe_id: str):
        """Prints the complete ChildOf hierarchy of a CWE."""
        print(f"\n{'='*70}")
        print(f"⬆️  ChildOf Hierarchy for CWE-{cwe_id}")
        print(f"{'='*70}")
        
        visited: Set[str] = set()
        current = cwe_id
        path = []
        
        while current and current not in visited:
            visited.add(current)
            
            name = self.get_element_name(current)
            type_str = self.get_element_type(current)
            
            path.append((current, name, type_str))
            
            parents = self.child_of.get(current, [])
            if not parents:
                break
            
            current = parents[0]
        
        if len(path) == 1:
            print("   ℹ️  No parent (it is already at the highest level)")
        else:
            for i, (id, name, type_str) in enumerate(path):
                indent = "  " * i
                arrow = "└─>" if i == len(path) - 1 else "├─>"
                icon = "📁" if type_str == "Category" else "📄"
                highlight = " (TOP)" if i == len(path) - 1 else ""
                
                print(f"{indent}{arrow} {icon} CWE-{id}: {name}{highlight}")

    def get_descendants(self, element_id: str, max_depth: Optional[int] = None) -> Dict[str, Dict[int, List[str]]]:
        """
        Return all descendants of a View, Category, or Weakness, automatically detecting
        what the element is and which hierarchy should be used.

        Args:
            element_id: ID of a View, Category, or Weakness.
            max_depth: Maximum depth to explore (0 = only direct children, None = full depth).

        Returns:
            Dictionary structured as:
            {
                "type": "View" | "Category" | "Weakness" | "Unknown",
                "by_view": {
                    view_id: { depth: [children] }
                }
            }
        """
        result = {
            "type": None,
            "by_view": {}
        }

        # --- Case 1: The element is a View ---------------------------------
        if element_id in self.views:
            result["type"] = "View"
            descendants = self._get_descendants_in_view(element_id, element_id, max_depth)
            result["by_view"][element_id] = descendants
            return result

        # --- Case 2: The element is a Category ------------------------------
        if element_id in self.categories:
            result["type"] = "Category"

            # Look for all views where this category appears
            for view_id, parents in self.view_parent_map.items():
                if element_id in parents:
                    descendants = self._get_descendants_in_view(view_id, element_id, max_depth)
                    result["by_view"][view_id] = descendants

            # If category is not present in any view, fallback to Has_Member
            if not result["by_view"]:
                result["by_view"]["no_view"] = self._get_descendants_in_categories(element_id, max_depth)

            return result

        # --- Case 3: Weakness → no descendants ------------------------------
        if element_id in self.weaknesses:
            result["type"] = "Weakness"
            result["by_view"] = {}
            return result

        # --- Case 4: Not found ----------------------------------------------
        result["type"] = "Unknown"
        return result

    def _get_descendants_in_view(self, view_id: str, start_id: str, max_depth: Optional[int]) -> Dict[int, List[str]]:
        """
        Collect descendants using the hierarchy defined inside a specific View.
        """
        results = defaultdict(list)
        queue = [(start_id, 0)]

        while queue:
            current, depth = queue.pop(0)

            # Skip the root element itself
            if depth != 0:
                results[depth].append(current)

            # Depth limit reached
            if max_depth is not None and depth >= max_depth:
                continue

            # Explore children
            for child in self.view_structure[view_id].get(current, []):
                queue.append((child, depth + 1))

        return results

    def _get_descendants_in_categories(self, category_id: str, max_depth: Optional[int]) -> Dict[int, List[str]]:
        """
        Collect descendants using Category → Has_Member relationships (no View involved).
        """
        results = defaultdict(list)
        queue = [(category_id, 0)]

        while queue:
            current, depth = queue.pop(0)

            # Skip the root element itself
            if depth != 0:
                results[depth].append(current)

            if max_depth is not None and depth >= max_depth:
                continue

            category = self.categories.get(current)
            if not category:
                continue

            for member in category.findall('.//cwe:Relationships/cwe:Has_Member', self.ns):
                child_id = member.get('CWE_ID')
                if child_id:
                    queue.append((child_id, depth + 1))

        return results


def main():
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description='CWE Navigator - Explore Common Weakness Enumeration hierarchy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cwec_latest.xml 120 --views 700 888
  %(prog)s cwec_latest.xml 79 --hierarchy
  %(prog)s cwec_latest.xml 89 --views 1000 --hierarchy
        """
    )
    
    parser.add_argument(
        'xml_file',
        help='Path to MITRE cwec_latest.xml file'
    )
    
    parser.add_argument(
        'cwe_id',
        help='CWE ID to analyze (e.g., 120, 79, 89)'
    )
    
    parser.add_argument(
        '--views',
        nargs='+',
        default=['700', '888', '1000', '1154'],
        help='List of View IDs to analyze (default: 700 888 1000)'
    )
    
    parser.add_argument(
        '--hierarchy',
        action='store_true',
        help='Show complete ChildOf hierarchy'
    )
    
    parser.add_argument(
        '--top-parent',
        action='store_true',
        help='Show only the top-level parent'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize navigator
        print(f"🔄 Loading XML file: {args.xml_file}")
        navigator = CWENavigator(args.xml_file)
        print("✅ File loaded successfully!\n")
        
        cwe_id = args.cwe_id

        if cwe_id.startswith("CWE-"):
            cwe_id = cwe_id[4:]
        
        # Show ChildOf hierarchy if requested
        if args.hierarchy:
            navigator.print_hierarchy(cwe_id)
        
        # Show top parent if requested
        if args.top_parent:
            top = navigator.get_top_parent(cwe_id)
            if top:
                name = navigator.get_element_name(top)
                print(f"\n🔝 Top Parent: CWE-{top} - {name}")
            else:
                print(f"\n⚠️  No top parent found for CWE-{cwe_id}")
        
        # Find and print paths in views
        paths = navigator.get_paths_in_views(cwe_id, args.views)
        navigator.print_paths(cwe_id, paths)
        
    except FileNotFoundError:
        print(f"❌ Error: File '{args.xml_file}' not found", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError as e:
        print(f"❌ Error parsing XML file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()